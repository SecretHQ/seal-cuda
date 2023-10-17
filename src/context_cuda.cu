#include "context_cuda.cuh"

namespace troy {

    void SEALContextCuda::initialize(const SEALContext& context) {
        // std::cout << "contextinit" << std::endl;
        for (auto& pair: context.context_data_map_) {
            context_data_map_.emplace(std::make_pair(
                pair.first,
                std::make_shared<ContextDataCuda>(std::move(ContextDataCuda(*pair.second)))
            ));
        // std::cout << "contextinit2" << std::endl;
        }
        // re-establish the chain
        for (auto& pair: context.context_data_map_) {
            ParmsID current_id = pair.first;
            auto prev = pair.second->prevContextData();
            if (prev) {
                context_data_map_.at(current_id)->prev_context_data_
                    = context_data_map_.at(prev->parmsID());
            }
            auto next = pair.second->nextContextData();
            if (next) {
                context_data_map_.at(current_id)->next_context_data_
                    = context_data_map_.at(next->parmsID());
            }
        }
        key_parms_id_ = context.keyParmsID();
        first_parms_id_ = context.firstParmsID();
        last_parms_id_ = context.lastParmsID();
        using_keyswitching_ = context.using_keyswitching();
    }
    
}