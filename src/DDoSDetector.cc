#include "DDoSDetector.hpp"

#include "PacketParser.hpp"
#include "api/Packet.hpp"
#include "CommandLine.hpp"
#include "SwitchImpl.hpp"
#include "OFAgentImpl.hpp"
#include <runos/core/logging.hpp>
#include <fluid/of13msg.hh>

#include <string>
#include <cmath>
#include <boost/chrono.hpp>
#include <unordered_map>

namespace runos {

REGISTER_APPLICATION(DDoSDetector, {"controller",
                                    "switch-manager",
                                    "topology",
                                    "of-server",
                                    "host-manager",
                                    ""})
                                
struct DDoSDetector::FlowRemovedHandler final
    : OFMessageHandler<of13::FlowRemoved> {
        
    DDoSDetector* app_;
    
    explicit FlowRemovedHandler(DDoSDetector* app) : app_{app} {}
    
    bool process(of13::FlowRemoved& fr, OFConnectionPtr conn) override {
        auto dpid = fr.cookie() & DPID_MASK;
        auto port_num = (fr.cookie() & PORT_NUMBER_MASK) >> 16;
        app_->flows_removed[dpid][port_num] += 1;
        app_->packets_in_removed_flow_[fr.cookie()] = fr.packet_count();
        return false;
    }
};

DDoSDetector::~DDoSDetector() {
    detection_thread_.interrupt();
}

void DDoSDetector::CollectFlowsInfo() {
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, long long>> flows_num; // dpid and port number to previous seen flow num
    std::unordered_map<uint64_t, long long> packets_in_flow; // flow cookie to packets num
    while (true) {
        std::vector<of13::FlowStats> flows;
        for (auto switch_ptr : switch_manager_->switches()) {
            auto dpid = switch_ptr->dpid();
            auto of_agent_future = of_server_->agent(dpid);
            of_agent_future.wait();
            auto of_agent = of_agent_future.get();

            ofp::flow_stats_request req;
            req.out_port = of13::OFPP_ANY;
            req.out_group = of13::OFPG_ANY;
            req.cookie_mask = 0;
            auto response_future = of_agent->request_flow_stats(req);
            response_future.wait();
            auto response = response_future.get();

            for (const auto& flow_stat : response) {
                flows.push_back(flow_stat);
            }
        }
        std::unordered_multimap<uint64_t, of13::FlowStats> host_to_flow;
        for (auto& flow : flows) {
            uint32_t cookie = flow.cookie() & 0x00000000FFFFFFFFULL;
            host_to_flow.emplace(std::make_pair(cookie, flow));
        }
        for (const auto& [name, host_ptr] : host_manager_->hosts()) {
            auto& host = *host_ptr;

            uint64_t dpid = host.switchID();
            uint32_t port = host.switchPort();
            uint64_t cookie = (port << 16) | dpid;
            
            double FlowCount = host_to_flow.count(cookie);
            if (FlowCount == 0 && flows_removed[dpid][port] == 0) {
                continue;
            }
            
            long long current_flows_num = 0;
            if (flows_num.count(dpid) > 0) {
                const auto& inner_flows_num_map = flows_num[dpid];
                if (inner_flows_num_map.count(port) > 0) {
                    current_flows_num = inner_flows_num_map.at(port);
                }
            }
            double SpeedOfFlowEntries = FlowCount - current_flows_num + flows_removed[dpid][port];
            if (SpeedOfFlowEntries < 0) {
                LOG(WARNING) << "Got values: " << FlowCount << " "
                            << current_flows_num << " " << flows_removed[dpid][port];
            }
            if (flows_num.count(dpid) == 0) {
                flows_num[dpid] = {};
            }
            flows_num[dpid][port] = FlowCount;
            
            long long sum_packet_count = 0;
            std::unordered_map<uint64_t, long long> new_packets_in_flows;
            const auto range = host_to_flow.equal_range(cookie);
            for (auto it = range.first; it != range.second; ++it) {
                auto& flow_stat = (*it).second;
                auto cookie = flow_stat.cookie();
                if (packets_in_flow.find(cookie) != packets_in_flow.end()) {
                    auto new_packets = flow_stat.packet_count() - packets_in_flow[cookie];
                    sum_packet_count += new_packets;
                    new_packets_in_flows[cookie] = new_packets;
                } else {
                    sum_packet_count += flow_stat.packet_count();
                    new_packets_in_flows[cookie] = flow_stat.packet_count();
                }
                packets_in_flow[cookie] = flow_stat.packet_count();
            }
            int current_host_flows_removed = 0;
            for (const auto& [flow_cookie, packets_num] : packets_in_removed_flow_) {
                if ((flow_cookie & (PORT_NUMBER_MASK | DPID_MASK)) == cookie) {
                    long long new_packets;
                    if (packets_in_flow.find(flow_cookie) != packets_in_flow.end()) {
                        new_packets = packets_num - packets_in_flow[flow_cookie];
                        packets_in_flow.erase(flow_cookie);
                    } else {
                        new_packets = packets_num;
                    }
                    sum_packet_count += new_packets;
                    new_packets_in_flows[flow_cookie] = new_packets;
                    current_host_flows_removed += 1;
                    packets_in_removed_flow_.erase(flow_cookie);
                }
            }
            long long flows_total = FlowCount + current_host_flows_removed;
            double AverageNumberOfFlowPackets = double(sum_packet_count) / flows_total;
            
            double VariationNumberOfFlowPackets = 0;
            for (auto [_, packets_num] : new_packets_in_flows) {
                VariationNumberOfFlowPackets += std::pow(
                    packets_num - AverageNumberOfFlowPackets,
                    2);
            }
            VariationNumberOfFlowPackets = std::sqrt(VariationNumberOfFlowPackets / flows_total);
            
            bool is_malicious = CheckIfMalicious({FlowCount, SpeedOfFlowEntries, 
                                                    AverageNumberOfFlowPackets,
                                                    VariationNumberOfFlowPackets});
            
            if (is_malicious) {
                LOG(INFO) << "Host on dpid " << dpid << " port " << port << " may be malicious!";
            }
            flows_removed[dpid][port] = 0;
        }
        if (packets_in_removed_flow_.size() != 0) {
            LOG(ERROR) << "not all removed flows seen";
            packets_in_removed_flow_.clear();
        }
        
        boost::this_thread::sleep_for(data_pickup_period_);
    }
}

bool DDoSDetector::CheckIfMalicious(std::array<double, features_num> features) {
    double res = 0;
    for (int i = 0; i < features_num; ++i) {
        res += (features[i] - mean_[i]) / scale_[i] * coefs_[i];
    }
    res += intercept_;
    if (show_debug_) {
        LOG(INFO) << "Got values: " << features[0] << " " << features[1] << " "
                   << features[2] << " " << features[3];
        LOG(INFO) << "Got result: " << res;
    }
    return res > 0;
}

void DDoSDetector::init(Loader* loader, const Config& config) {
    switch_manager_ = SwitchManager::get(loader);
    of_server_ = OFServer::get(loader);
    host_manager_ = HostManager::get(loader);
    data_pickup_period_ = boost::chrono::seconds(config_get(
        config_cd(config, "ddos-detector"), "data-pickup-period", 3));
        
    CommandLine* cli = CommandLine::get(loader);
    cli->register_command(
        cli_pattern(R"(debug\s+on)"),
        [=](cli_match const& match) {
            this->show_debug_ = true;
        });
    cli->register_command(
        cli_pattern(R"(debug\s+off)"),
        [=](cli_match const& match) {
            this->show_debug_ = false;
        });
        
    std::string weights_file_name = config_get(
        config_cd(config, "ddos-detector"), "weights_file", "weights");
    std::ifstream weights_file(weights_file_name);
    for (int i = 0; i < features_num; ++i) {
        weights_file >> scale_[i];
    }
    for (int i = 0; i < features_num; ++i) {
        weights_file >> mean_[i];
    }
    for (int i = 0; i < features_num; ++i) {
        weights_file >> coefs_[i];
    }
    weights_file >> intercept_;
    weights_file.close();
    
    enabled_ = config_get(
        config_cd(config, "ddos-detector"), "enabled", true);
    
    handler_.reset(new FlowRemovedHandler(this));
    Controller::get(loader)->register_handler(handler_, -200);
}

void DDoSDetector::startUp(class Loader*) {
    for (auto switch_ptr : switch_manager_->switches()) {
        auto dpid = switch_ptr->dpid();
        auto of_agent_future = of_server_->agent(dpid);
        of_agent_future.wait();
        auto of_agent = of_agent_future.get();
        for (const auto& port_ptr : (*switch_ptr).ports()) {
            // TODO make this just to ports connected to switches
            // TODO this relies on topology does not change
            unsigned port_num = (*port_ptr).number();
            flows_removed[dpid][port_num] = 0;
        }
    }
    if (enabled_) {
        detection_thread_ = boost::thread([&]() {
            this->CollectFlowsInfo();
        });
    }
}

} // namespace runos
