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

namespace runos {

REGISTER_APPLICATION(DDoSDetector, {"controller",
                                    "switch-manager",
                                    "topology",
                                    "of-server",
                                    ""})
                                
struct DDoSDetector::FlowRemovedHandler final
    : OFMessageHandler<of13::FlowRemoved> {
        
    DDoSDetector* app_;
    
    explicit FlowRemovedHandler(DDoSDetector* app) : app_{app} {}
    
    bool process(of13::FlowRemoved& fr, OFConnectionPtr conn) override {
        app_->flows_removed += 1;
        app_->packets_in_removed_flow_[fr.cookie()] = fr.packet_count();
        return false;
    }
};

DDoSDetector::~DDoSDetector() {
    detection_thread_.interrupt();
}

void DDoSDetector::CollectFlowsInfo() {
    flows_removed = 0;
    long long flows_num = 0;
    std::unordered_map<uint64_t, long long> packets_in_flow;
    while (true) {
        // truly there must be only one switch
        for (auto switch_ptr : switch_manager_->switches()) {
            auto dpid = switch_ptr->dpid();
            auto of_agent_future = of_server_->agent(dpid);
            of_agent_future.wait();
            auto of_agent = of_agent_future.get();
            for (const auto& port_ptr : (*switch_ptr).ports()) {
                unsigned host_num = (*port_ptr).number();
                LOG(INFO) << "port found: " << host_num;
                ofp::flow_stats_request req;
                req.out_port = of13::OFPP_ANY;
                req.out_group = of13::OFPG_ANY;
                req.cookie = host_num;
                req.cookie_mask = 0x00000000FFFFFFFFULL;
                
                auto response_future = of_agent->request_flow_stats(req);
                response_future.wait();
                auto response = response_future.get();
                
                double FlowCount = response.size();
                if (FlowCount == 0) {
                    LOG(INFO) << "flows not found";
                    continue;
                }
                
                double SpeedOfFlowEntries = FlowCount - flows_num + flows_removed;
                flows_num = FlowCount;
                
                long long sum_packet_count = 0;
                std::unordered_map<uint64_t, long long> new_packets_in_flows;
                for (auto flow_stat : response) {
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
                for (auto [cookie, packets_num] : packets_in_removed_flow_) {
                    long long new_packets;
                    if (packets_in_flow.find(cookie) != packets_in_flow.end()) {
                        new_packets = packets_num - packets_in_flow[cookie];
                        packets_in_flow.erase(cookie);
                    } else {
                        new_packets = packets_num;
                    }
                    sum_packet_count += new_packets;
                    new_packets_in_flows[cookie] = new_packets;
                }
                long long flows_total = FlowCount + packets_in_removed_flow_.size();
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
                    LOG(INFO) << "Host " << host_num << " may be malicious!";
                }
            }
            LOG(INFO) << "all ports checked";
        }
        packets_in_removed_flow_.clear();
        flows_removed = 0;
        
        boost::this_thread::sleep_for(data_pickup_period_);
    }
}

bool DDoSDetector::CheckIfMalicious(std::array<double, features_num> features) {
    double res = 0;
    for (int i = 0; i < features_num; ++i) {
        features[i] -= mean_[i];
        features[i] /= scale_[i];
        res += features[i] * coefs_[i];
    }
    res += intercept_;
    return res > 0;
}

void DDoSDetector::init(Loader* loader, const Config& config) {
    switch_manager_ = SwitchManager::get(loader);
    of_server_ = OFServer::get(loader);
    data_pickup_period_ = boost::chrono::seconds(config_get(
        config_cd(config, "ddos-detector"), "data-pickup-period", 3));
        
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
    
    handler_.reset(new FlowRemovedHandler(this));
    Controller::get(loader)->register_handler(handler_, -200);
}

void DDoSDetector::startUp(class Loader*) {
    detection_thread_ = boost::thread([&]() {
        this->CollectFlowsInfo();
    });
}

} // namespace runos
