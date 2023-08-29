#pragma once

#include "Application.hpp"
#include "Config.hpp"
#include "Loader.hpp"
#include "SwitchManager.hpp"
#include "OFServer.hpp"
#include "api/SwitchFwd.hpp"
#include "oxm/openflow_basic.hh"

#include "../../host-manager/include/HostManager.hpp"

#include <fstream>
#include <unordered_map>
#include <array>
#include <atomic>

#include <boost/thread/thread.hpp>

namespace runos {

using SwitchPtr = safe::shared_ptr<Switch>;
namespace of13 = fluid_msg::of13;

const inline int FEATURES_NUM = 4;
const inline unsigned long long PORT_NUMBER_MASK = 0x00000000FFFF0000ULL;
const inline unsigned long long DPID_MASK = 0x000000000000FFFFULL;

class DDoSDetector : public Application
{
    Q_OBJECT
    SIMPLE_APPLICATION(DDoSDetector, "ddos-detector")
public:
    void init(Loader* loader, const Config& config) override;
    void startUp(class Loader*) override;
    bool CheckIfMalicious(std::array<double, FEATURES_NUM> features);
    void CollectFlowsInfo();
    ~DDoSDetector();

private:
    static const inline int features_num = FEATURES_NUM;
    struct FlowRemovedHandler;
    std::shared_ptr<FlowRemovedHandler> handler_;
    SwitchManager* switch_manager_;
    OFServer* of_server_;
    HostManager* host_manager_;
	
    boost::chrono::seconds data_pickup_period_;
    boost::thread detection_thread_;
    
    std::array<double, FEATURES_NUM> scale_;
    std::array<double, FEATURES_NUM> mean_;
    std::array<double, FEATURES_NUM> coefs_;
    double intercept_;
    
    std::unordered_map<uint64_t, std::atomic_llong> packets_in_removed_flow_; // flow cookie to packets number
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::atomic_llong>> flows_removed; // dpid and port number to removed flows num
    
    bool show_debug_ = false;
    bool enabled_;
};

} // namespace runos
