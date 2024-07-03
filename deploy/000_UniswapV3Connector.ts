import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import verify from "../helper-functions";
import config from "config";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const { deployments, getNamedAccounts, network } = hre;
    const { deploy } = deployments;
    const { deployer } = await getNamedAccounts();

    if (
        network.name == "hardhat" ||
        network.name == "bsquared"
    ) {
        const uniswapV3SwapRouter = config.get("uniswap_v3_swap_router");
        const uniswapV3Quoter = config.get("uniswap_v3_quoter");

        const deployedContract = await deploy("UniswapV3Connector", {
            from: deployer,
            log: true,
            skipIfAlreadyDeployed: true,
            args: ["UniswapV3", uniswapV3SwapRouter, uniswapV3Quoter]
        });

        if (
            network.name != "hardhat" &&
            process.env.ETHERSCAN_API_KEY &&
            process.env.VERIFY_OPTION == "1"
        ) {
            await verify(
                deployedContract.address,
                ["UniswapV3", uniswapV3SwapRouter, uniswapV3Quoter],
                "contracts/swap_connectors/UniswapV3Connector.sol:UniswapV3Connector"
            );
        }
    }
};

export default func;
func.tags = ["UniswapV3Connector"];
