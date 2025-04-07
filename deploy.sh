#!/bin/bash
set -e

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Path to the configuration file (JSON format)
CONFIG_FILE="chains.json"
RESULTS_FILE="deployment_results.json"
LOG_DIR="deployment_logs"

# Ensure log directory exists
mkdir -p $LOG_DIR

# Check if required tools are installed
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    which forge >/dev/null 2>&1 || { echo -e "${RED}Error: forge not found. Please install foundry.${NC}"; exit 1; }
    which jq >/dev/null 2>&1 || { echo -e "${RED}Error: jq not found. Please install jq.${NC}"; exit 1; }
    which cast >/dev/null 2>&1 || { echo -e "${RED}Error: cast not found. Please install foundry.${NC}"; exit 1; }
}

# Function to deploy to a specific chain
deploy_to_chain() {
    local chain_id=$1
    local chain_name=$2
    local rpc_url=$3
    local explorer_url=$4
    local api_key=$5
    
    local deployer=$(jq -r '.deployer' $CONFIG_FILE)
    local gas_limit=$(jq -r '.gas.limit' $CONFIG_FILE)
    local gas_price=$(jq -r '.gas.price' $CONFIG_FILE)
    local verify=$(jq -r '.verification.enabled' $CONFIG_FILE)
    local admin=$(jq -r '.constructor.admin' $CONFIG_FILE)
    local relayer=$(jq -r '.constructor.relayer' $CONFIG_FILE)
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local log_file="${LOG_DIR}/${chain_name}_${timestamp}.log"
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Deploying to ${chain_name} (Chain ID: ${chain_id})${NC}"
    echo -e "${BLUE}RPC URL: ${rpc_url}${NC}"
    echo -e "${BLUE}Log file: ${log_file}${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Build the deployment command
    local deploy_cmd="forge script script/Deployer.sol:Deployer"
    deploy_cmd+=" --rpc-url ${rpc_url}"
    deploy_cmd+=" --broadcast"
    deploy_cmd+=" -vv"
    deploy_cmd+=" --account ${deployer}"
    deploy_cmd+=" --gas-limit ${gas_limit}"
    
    if [ "$gas_price" != "auto" ]; then
        deploy_cmd+=" --gas-price ${gas_price}"
    fi
    
    # Execute deployment
    echo -e "${YELLOW}Executing deployment command...${NC}"
    echo "Command: $deploy_cmd" | tee -a "$log_file"
    
    # Run deployment and capture output
    if eval $deploy_cmd 2>&1 | tee -a "$log_file"; then
        echo -e "${GREEN}Deployment to ${chain_name} succeeded${NC}"
        
        # Extract contract addresses from the log file
        signerRegistryImpl=$(grep "SignerRegistry implementation deployed at:" "$log_file" | awk '{print $NF}')
        signerRegistryProxy=$(grep "SignerRegistry proxy deployed at:" "$log_file" | awk '{print $NF}')
        contractRegistryImpl=$(grep "ContractRegistry implementation deployed at:" "$log_file" | awk '{print $NF}')
        contractRegistryProxy=$(grep "ContractRegistry proxy deployed at:" "$log_file" | awk '{print $NF}')
        walletFactoryImpl=$(grep "WalletFactory implementation deployed at:" "$log_file" | awk '{print $NF}')
        walletFactoryProxy=$(grep "WalletFactory proxy deployed at:" "$log_file" | awk '{print $NF}')
        gasStationFactoryImpl=$(grep "GasStationFactory implementation deployed at:" "$log_file" | awk '{print $NF}')
        gasStationFactoryProxy=$(grep "GasStationFactory proxy deployed at:" "$log_file" | awk '{print $NF}')
        
        # Create a result object
        local result=$(cat <<EOF
{
  "chainId": $chain_id,
  "chainName": "$chain_name",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "success",
  "addresses": {
    "signerRegistryImpl": "$signerRegistryImpl",
    "signerRegistryProxy": "$signerRegistryProxy",
    "contractRegistryImpl": "$contractRegistryImpl",
    "contractRegistryProxy": "$contractRegistryProxy",
    "walletFactoryImpl": "$walletFactoryImpl",
    "walletFactoryProxy": "$walletFactoryProxy",
    "gasStationFactoryImpl": "$gasStationFactoryImpl",
    "gasStationFactoryProxy": "$gasStationFactoryProxy"
  }
}
EOF
)
        
        # Handle verification if enabled
        if [ "$verify" = "true" ] && [ ! -z "$api_key" ]; then
            echo -e "${YELLOW}Verifying contracts on ${explorer_url}${NC}"
            
            # Verify implementations (You may need to adjust the exact verification commands based on your contracts)
            echo "Verifying SignerRegistry implementation..." | tee -a "$log_file"
            forge verify-contract --chain-id $chain_id --watch --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$signerRegistryImpl" contracts/SignerRegistry.sol:SignerRegistry 2>&1 | tee -a "$log_file"
            
            echo "Verifying ContractRegistry implementation..." | tee -a "$log_file"
            forge verify-contract --chain-id $chain_id --watch --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$contractRegistryImpl" contracts/ContractRegistry.sol:ContractRegistry 2>&1 | tee -a "$log_file"
            
            echo "Verifying WalletFactory implementation..." | tee -a "$log_file"
            forge verify-contract --chain-id $chain_id --watch --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$walletFactoryImpl" contracts/WalletFactory.sol:WalletFactory 2>&1 | tee -a "$log_file"
            
            echo "Verifying GasStationFactory implementation..." | tee -a "$log_file"
            forge verify-contract --chain-id $chain_id --watch --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$gasStationFactoryImpl" contracts/GasStationFactory.sol:GasStationFactory 2>&1 | tee -a "$log_file"
            
            # Verify proxies with constructor args
            echo "Verifying SignerRegistry proxy..." | tee -a "$log_file"
            signerRegistryProxyArgs=$(cast abi-encode "constructor(address,bytes)" "$signerRegistryImpl" "$(cast calldata 'initialize(address)' "$admin")")
            forge verify-contract --chain-id $chain_id --watch --constructor-args "$signerRegistryProxyArgs" --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$signerRegistryProxy" contracts/SignerRegistryProxy.sol:SignerRegistryProxy 2>&1 | tee -a "$log_file"
            
            echo "Verifying ContractRegistry proxy..." | tee -a "$log_file"
            contractRegistryProxyArgs=$(cast abi-encode "constructor(address,bytes)" "$contractRegistryImpl" "$(cast calldata 'initialize(address,address)' "$admin" "$signerRegistryProxy")")
            forge verify-contract --chain-id $chain_id --watch --constructor-args "$contractRegistryProxyArgs" --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$contractRegistryProxy" contracts/ContractRegistryProxy.sol:ContractRegistryProxy 2>&1 | tee -a "$log_file"
            
            echo "Verifying WalletFactory proxy..." | tee -a "$log_file"
            walletFactoryProxyArgs=$(cast abi-encode "constructor(address,bytes)" "$walletFactoryImpl" "$(cast calldata 'initialize(address,address,address,address)' "$admin" "$relayer" "$contractRegistryProxy" "$signerRegistryProxy")")
            forge verify-contract --chain-id $chain_id --watch --constructor-args "$walletFactoryProxyArgs" --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$walletFactoryProxy" contracts/WalletFactoryProxy.sol:WalletFactoryProxy 2>&1 | tee -a "$log_file"
            
            echo "Verifying GasStationFactory proxy..." | tee -a "$log_file"
            gasStationFactoryProxyArgs=$(cast abi-encode "constructor(address,bytes)" "$gasStationFactoryImpl" "$(cast calldata 'initialize(address,address,address)' "$admin" "$relayer" "$signerRegistryProxy")")
            forge verify-contract --chain-id $chain_id --watch --constructor-args "$gasStationFactoryProxyArgs" --compiler-version v0.8.17+commit.8df45f5f --num-of-optimizations 200 --etherscan-api-key $api_key "$gasStationFactoryProxy" contracts/GasStationFactoryProxy.sol:GasStationFactoryProxy 2>&1 | tee -a "$log_file"
        fi
        
        echo -e "${GREEN}Deployment to ${chain_name} completed${NC}"
        echo "$result"
        echo "$result" > "${LOG_DIR}/${chain_name}_result.json"
        
        # Add to results file
        if [ -f "$RESULTS_FILE" ]; then
            # Update existing results file
            local temp_file="${RESULTS_FILE}.tmp"
            jq --argjson newChain "$result" '.deployments += [$newChain]' "$RESULTS_FILE" > "$temp_file"
            mv "$temp_file" "$RESULTS_FILE"
        else
            # Create new results file
            echo '{"deployments":['"$result"']}' > "$RESULTS_FILE"
        fi
        
        return 0
    else
        echo -e "${RED}Deployment to ${chain_name} failed${NC}"
        
        # Create a failure result object
        local failure=$(cat <<EOF
{
  "chainId": $chain_id,
  "chainName": "$chain_name",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "failed",
  "logFile": "$log_file"
}
EOF
)
        # Add to results file
        if [ -f "$RESULTS_FILE" ]; then
            # Update existing results file
            local temp_file="${RESULTS_FILE}.tmp"
            jq --argjson newChain "$failure" '.failures += [$newChain]' "$RESULTS_FILE" > "$temp_file"
            mv "$temp_file" "$RESULTS_FILE"
        else
            # Create new results file
            echo '{"deployments":[], "failures":['"$failure"']}' > "$RESULTS_FILE"
        fi
        
        return 1
    fi
}

# Main function
main() {
    check_dependencies
    
    echo -e "${BLUE}Starting multi-chain deployment process...${NC}"
    echo -e "${YELLOW}Using config file: ${CONFIG_FILE}${NC}"
    
    # Initialize results file
    echo '{"deployments":[], "failures":[]}' > "$RESULTS_FILE"
    
    # Get all enabled chains
    local enabled_chains=$(jq -c '.chains[] | select(.enabled == true)' "$CONFIG_FILE")
    local chain_count=$(echo "$enabled_chains" | wc -l | tr -d ' ')
    
    echo -e "${BLUE}Found ${chain_count} enabled chains for deployment${NC}"
    
    # Process each chain
    echo "$enabled_chains" | while read -r chain; do
        local chain_id=$(echo "$chain" | jq -r '.id')
        local chain_name=$(echo "$chain" | jq -r '.name')
        local rpc_url=$(echo "$chain" | jq -r '.rpc')
        local explorer_url=$(echo "$chain" | jq -r '.explorer')
        local api_key=$(echo "$chain" | jq -r '.api_key')
        
        deploy_to_chain "$chain_id" "$chain_name" "$rpc_url" "$explorer_url" "$api_key"
    done
    
    echo -e "${GREEN}All deployments completed!${NC}"
    echo -e "${BLUE}Results saved to ${RESULTS_FILE}${NC}"
    echo -e "${BLUE}Detailed logs saved to ${LOG_DIR}/${NC}"
    
    # Display summary
    local successful=$(jq '.deployments | length' "$RESULTS_FILE")
    local failed=$(jq '.failures | length' "$RESULTS_FILE")
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Deployment Summary:${NC}"
    echo -e "${GREEN}Successful: ${successful}${NC}"
    echo -e "${RED}Failed: ${failed}${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Run the main function
main "$@"
