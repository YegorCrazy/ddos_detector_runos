#pragma once

#include "Application.hpp"
#include "Config.hpp"
#include "Loader.hpp"
#include "SwitchManager.hpp"
#include "OFServer.hpp"
#include "api/SwitchFwd.hpp"
#include "oxm/openflow_basic.hh"

#include <fstream>
#include <unordered_map>
#include <array>

#include <boost/thread/thread.hpp>

namespace runos {

using SwitchPtr = safe::shared_ptr<Switch>;
namespace of13 = fluid_msg::of13;

const inline int FEATURES_NUM = 4;

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
	
    boost::chrono::seconds data_pickup_period_;
    boost::thread detection_thread_;
    
    std::array<double, FEATURES_NUM> scale_;
    std::array<double, FEATURES_NUM> mean_;
    std::array<double, FEATURES_NUM> coefs_;
    double intercept_;
    
    std::unordered_map<uint64_t, long long> packets_in_removed_flow_;
    long long flows_removed = 0;
};

} // namespace runos
