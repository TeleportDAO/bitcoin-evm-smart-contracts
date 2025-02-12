import * as dotenv from "dotenv";
import { HardhatUserConfig } from "hardhat/config";
import '@openzeppelin/hardhat-upgrades';
import "@nomiclabs/hardhat-etherscan";
import "@nomiclabs/hardhat-waffle";
import "@typechain/hardhat";
import "hardhat-gas-reporter";
import "solidity-coverage";
import "hardhat-deploy";
import "hardhat-deploy-tenderly";
import "hardhat-contract-sizer";

dotenv.config();

const config: HardhatUserConfig = {
	solidity: {
		compilers: [
			{
				version: "0.5.16",
				settings: {
					optimizer: {
						enabled: true
					},
				},
			},
			{
				version: "0.6.6",
				settings: {
					optimizer: {
						enabled: true
					},
				},
			},
			{
				version: "0.8.4",
				settings: {
					optimizer: {
						enabled: true,
						runs: 1,
					},
				},
			}
		],
	},
	networks: {
		ethereum: {
			url: "https://ethereum-rpc.publicnode.com",
			chainId: 1,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		arbitrum: {
			url: "https://arbitrum-one.publicnode.com",
			chainId: 42161,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		optimism: {
			url: "https://optimism-rpc.publicnode.com",
			chainId: 10,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		sepolia: {
			url: "https://ethereum-sepolia-rpc.publicnode.com",
			chainId: 11155111,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		polygon: {
			url: "https://rpc-mainnet.matic.quiknode.pro",
			chainId: 137,
			accounts: [process.env.PRIVATE_KEY ?? ""],
			gasPrice: 130851301205
		},
		base: {
			url: "https://base.llamarpc.com",
			chainId: 8453,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		unichain: {
			url: "https://mainnet.unichain.org",
			chainId: 130,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		bsquared: {
			url: "https://rpc.bsquared.network",
			chainId: 223,
			accounts: [process.env.PRIVATE_KEY ?? ""],
		},
		amoy: {
			url: "https://rpc-amoy.polygon.technology",
			chainId: 80002,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		bsc: {
			url: "https://bsc-dataseed.binance.org/",
			chainId: 56,
			accounts: [process.env.PRIVATE_KEY ?? ""]
		},
		bob: {
			url: "https://rpc.gobob.xyz/",
			chainId: 60808,
			accounts: [process.env.PRIVATE_KEY ?? ""],
		},
		hardhat: {
			allowUnlimitedContractSize: true,
		},
	},	
  	paths: {
		artifacts: "artifacts",
		deploy: "deploy",
		deployments: "deployments",
  	},
  	typechain: {
		outDir: "src/types",
		target: "ethers-v5",
  	},
  	namedAccounts: {
		deployer: {
			default: 0,
		},
  	},
  	gasReporter: {
		enabled: true,
		currency: "USD",
  	},
  	etherscan: {
		apiKey: {
			ethereum: process.env.ETHERSCAN_API_KEY??"",
    		polygon: process.env.ETHERSCAN_API_KEY??"",
			base: process.env.ETHERSCAN_API_KEY??"",
			bsc: process.env.ETHERSCAN_API_KEY??"",
			arbitrum: process.env.ETHERSCAN_API_KEY??"",
			optimism: process.env.ETHERSCAN_API_KEY??"",
			bsquared: process.env.ETHERSCAN_API_KEY??"",
			amoy: process.env.ETHERSCAN_API_KEY??"",
			sepolia: process.env.ETHERSCAN_API_KEY??"",
			bob: process.env.ETHERSCAN_API_KEY??"",
			unichain: process.env.ETHERSCAN_API_KEY??""
  		},
		customChains: [
			{
				network: "ethereum",
				chainId: 1,
				urls: {
					apiURL: "https://api.etherscan.io/api",
					browserURL: "https://etherscan.io/"
				}
			},
			{
				network: "polygon",
				chainId: 137,
				urls: {
					apiURL: "https://api.polygonscan.com/api",
					browserURL: "https://polygonscan.com/"
				}
			},
			{
				network: "base",
				chainId: 8453,
				urls: {
					apiURL: "https://api.basescan.org/api",
					browserURL: "https://basescan.org/"
				}
			},
			{
				network: "bsc",
				chainId: 56,
				urls: {
					apiURL: "https://api.bscscan.com/api",
					browserURL: "https://bscscan.com/"
				}
			},
			{
				network: "arbitrum",
				chainId: 42161,
				urls: {
					apiURL: "https://api.arbiscan.io/api",
					browserURL: "https://arbiscan.com/"
				}
			},
			{
				network: "optimism",
				chainId: 10,
				urls: {
					apiURL: "https://api-optimistic.etherscan.io/api",
					browserURL: "https://optimism.etherscan.io/"
				}
			},
			{
				network: "unichain",
				chainId: 130,
				urls: {
					apiURL: "https://unichain.blockscout.com/api",
					browserURL: "https://unichain.blockscout.com/"
				}
			},
			{
				network: "bsquared",
				chainId: 223,
				urls: {
					apiURL: "https://explorer.bsquared.network/api",
					browserURL: "https://explorer.bsquared.network"
				}
			},
			{
				network: "bob",
				chainId: 60808,
				urls: {
					apiURL: "https://explorer.gobob.xyz/api",
					browserURL: "https://explorer.gobob.xyz/"
				}
			},
			{
				network: "amoy",
				chainId: 80002,
				urls: {
					apiURL: "https://api-amoy.polygonscan.com/api",
					browserURL: "https://amoy.polygonscan.com/"
				}
			},
			{
				network: "sepolia",
				chainId: 11155111,
				urls: {
					apiURL: "https://api-sepolia.etherscan.io/api",
					browserURL: "https://sepolia.etherscan.io/"
				}
			}
		]
  	},
};

export default config;
