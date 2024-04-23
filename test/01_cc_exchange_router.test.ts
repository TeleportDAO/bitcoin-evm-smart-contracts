const CC_EXCHANGE_REQUESTS = require('./test_fixtures/ccExchangeRequests.json');
require('dotenv').config({path:"../../.env"});

import { expect } from "chai";
import { deployments, ethers } from "hardhat";
import { Signer, BigNumber, Contract } from "ethers";
import { deployMockContract, MockContract } from "@ethereum-waffle/mock-contract";

import { UniswapV2Pair } from "../src/types/UniswapV2Pair";
import { UniswapV2Pair__factory } from "../src/types/factories/UniswapV2Pair__factory";
import { UniswapV2Factory } from "../src/types/UniswapV2Factory";
import { UniswapV2Factory__factory } from "../src/types/factories/UniswapV2Factory__factory";
import { UniswapV2Router02 } from "../src/types/UniswapV2Router02";
import { UniswapV2Router02__factory } from "../src/types/factories/UniswapV2Router02__factory";
import { UniswapV2Connector } from "../src/types/UniswapV2Connector";
import { UniswapV2Connector__factory } from "../src/types/factories/UniswapV2Connector__factory";

import { CcExchangeRouterProxy__factory } from "../src/types/factories/CcExchangeRouterProxy__factory";
import { CcExchangeRouterLogic__factory } from "../src/types/factories/CcExchangeRouterLogic__factory";
import { CcExchangeRouterLogicLibraryAddresses } from "../src/types/factories/CcExchangeRouterLogic__factory";

import { LockersManagerProxy__factory } from "../src/types/factories/LockersManagerProxy__factory";
import { LockersManagerLogic__factory } from "../src/types/factories/LockersManagerLogic__factory";
import { LockersManagerLogicLibraryAddresses } from "../src/types/factories/LockersManagerLogic__factory";

import { LockersManagerLib } from "../src/types/LockersManagerLib";
import { LockersManagerLib__factory } from "../src/types/factories/LockersManagerLib__factory";

import { CcExchangeRouterLib } from "../src/types/CcExchangeRouterLib";
import { CcExchangeRouterLib__factory } from "../src/types/factories/CcExchangeRouterLib__factory";

import { TeleBTCLogic } from "../src/types/TeleBTCLogic";
import { TeleBTCLogic__factory } from "../src/types/factories/TeleBTCLogic__factory";
import { TeleBTCProxy } from "../src/types/TeleBTCProxy";
import { TeleBTCProxy__factory } from "../src/types/factories/TeleBTCProxy__factory";
import { ERC20 } from "../src/types/ERC20";
import { Erc20__factory } from "../src/types/factories/Erc20__factory";
import { WETH } from "../src/types/WETH";
import { WETH__factory } from "../src/types/factories/WETH__factory";

import { BurnRouterLib } from "../src/types/BurnRouterLib";
import { BurnRouterLib__factory } from "../src/types/factories/BurnRouterLib__factory";

import { BurnRouterProxy__factory } from "../src/types/factories/BurnRouterProxy__factory";
import { BurnRouterLogic__factory } from "../src/types/factories/BurnRouterLogic__factory";
import { BurnRouterLogicLibraryAddresses } from "../src/types/factories/BurnRouterLogic__factory";

import { takeSnapshot, revertProvider } from "./block_utils";

import Web3 from 'web3'
const abiUtils = new Web3().eth.abi
const web3 = new Web3();

describe("CcExchangeRouter", async () => {

    let snapshotId: any;

    // Constants
    const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    const ONE_ADDRESS = "0x0000000000000000000000000000000000000011";
    const DUMMY_ADDRESS = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    const THIRD_PARTY_ADDRESS = "0x0000000000000000000000000000000000000200"
    const CHAIN_ID = 1;
    const APP_ID = 1;
    const PROTOCOL_PERCENTAGE_FEE = 10; // Means %0.1
    let THIRD_PARTY_PERCENTAGE_FEE = 30 ; // Means %0.3
    const LOCKER_PERCENTAGE_FEE = 20; // Means %0.2
    const PRICE_WITH_DISCOUNT_RATIO = 9500; // Means %95
    const STARTING_BLOCK_NUMBER = 1;
    const TREASURY = "0x0000000000000000000000000000000000000002";

    // Bitcoin public key (32 bytes)
    let LOCKER1_LOCKING_SCRIPT = '0xa9144062c8aeed4f81c2d73ff854a2957021191e20b687';
    let LOCKER_TARGET_ADDRESS = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";

    let LOCKER_RESCUE_SCRIPT_P2PKH = "0x12ab8dc588ca9d5787dde7eb29569da63c3a238c";
    let LOCKER_RESCUE_SCRIPT_P2PKH_TYPE = 1; // P2PKH

    let USER_SCRIPT_P2PKH = "0x12ab8dc588ca9d5787dde7eb29569da63c3a238c";
    let USER_SCRIPT_P2PKH_TYPE = 1; // P2PKH

    let telePortTokenInitialSupply = BigNumber.from(10).pow(18).mul(10000);
    let minRequiredTNTLockedAmount = BigNumber.from(10).pow(18).mul(5);
    let collateralRatio = 20000;
    let liquidationRatio = 15000;

    // Accounts
    let proxyAdmin: Signer;
    let deployer: Signer;
    let signer1: Signer;
    let locker: Signer;
    let proxyAdminAddress: string;
    let deployerAddress: string;
    let lockerAddress: string;

    // Contracts
    let exchangeConnector: UniswapV2Connector;
    let uniswapV2Router02: UniswapV2Router02;
    let uniswapV2Pair: UniswapV2Pair;
    let uniswapV2Factory: UniswapV2Factory;
    let ccExchangeRouter: Contract;
    let lockersLib: LockersManagerLib;
    let lockers: Contract;
    let teleBTC: TeleBTC;
    let teleportDAOToken: ERC20;
    let exchangeToken: ERC20;
    let anotherExchangeToken: ERC20;
    let weth: WETH;
    let burnRouterLib: BurnRouterLib;
    let burnRouter: Contract;

    // Mock contracts
    let mockBitcoinRelay: MockContract;
    let mockInstantRouter: MockContract;
    let mockPriceOracle: MockContract;
    let mockAcross: MockContract;
    let mockLockers: MockContract;

    //
    let uniswapV2Pair__factory: UniswapV2Pair__factory;

    before(async () => {
        // Sets accounts
        [proxyAdmin, deployer, signer1, locker] = await ethers.getSigners();
        proxyAdminAddress = await proxyAdmin.getAddress();
        deployerAddress = await deployer.getAddress();
        lockerAddress = await locker.getAddress();

        teleportDAOToken = await deployTeleportDAOToken();

        // Mocks relay contract
        const bitcoinRelayContract = await deployments.getArtifact(
            "IBitcoinRelay"
        );
        mockBitcoinRelay = await deployMockContract(
            deployer,
            bitcoinRelayContract.abi
        );

        const priceOracleContract = await deployments.getArtifact(
            "IPriceOracle"
        );
        mockPriceOracle = await deployMockContract(
            deployer,
            priceOracleContract.abi
        );

        await mockPriceOracle.mock.equivalentOutputAmount.returns(100000)

        // Mocks checkTxProof of bitcoinRelay
        // We don't pass arguments since the request was modified and the txId is not valid
        await mockBitcoinRelay.mock.getBlockHeaderFee.returns(0); // Fee of relay
        await mockBitcoinRelay.mock.checkTxProof.returns(true);
        await mockBitcoinRelay.mock.finalizationParameter.returns(5)

        // Mocks across
        const across = await deployments.getArtifact(
            "SpokePoolInterface"
        );
        mockAcross = await deployMockContract(
            deployer,
            across.abi
        )

        mockAcross.mock.deposit.returns()

        //TODO ?!
        // Mocks instant router contract
        // const instantRouterContract = await deployments.getArtifact(
        //     "IInstantRouter"
        // );
        // mockInstantRouter = await deployMockContract(
        //     deployer,
        //     instantRouterContract.abi
        // );

        // await mockInstantRouter.mock.payBackLoan.returns(true);

        // Deploys teleBTC contract
        const teleBTCLogicFactory = new TeleBTCLogic__factory(deployer);
        const teleBTCLogic = await teleBTCLogicFactory.deploy();

        const teleBTCProxyFactory = new TeleBTCProxy__factory(deployer);
        const teleBTCProxy = await teleBTCProxyFactory.deploy(
            teleBTCLogic.address,    
            proxyAdminAddress,
            "0x"
        );
        
        teleBTC = await teleBTCLogic.attach(
            teleBTCProxy.address
        );

        await teleBTC.initialize(
            "TeleportDAO-BTC",
            "teleBTC"
        );

        // Deploys WETH contract
        const wethFactory = new WETH__factory(deployer);
        weth = await wethFactory.deploy(
            "WrappedEthereum",
            "WETH"
        );

        // Deploys uniswapV2Factory
        const uniswapV2FactoryFactory = new UniswapV2Factory__factory(deployer);
        uniswapV2Factory = await uniswapV2FactoryFactory.deploy(
            deployerAddress
        );

        // Creates uniswapV2Pair__factory object
        uniswapV2Pair__factory = new UniswapV2Pair__factory(deployer);

        // Deploys uniswapV2Router02 contract
        const uniswapV2Router02Factory = new UniswapV2Router02__factory(deployer);
        uniswapV2Router02 = await uniswapV2Router02Factory.deploy(
            uniswapV2Factory.address,
            weth.address // WETH
        );

        // Deploys uniswap connector
        const exchangeConnectorFactory = new UniswapV2Connector__factory(deployer);
        exchangeConnector = await exchangeConnectorFactory.deploy(
            "TheExchangeConnector",
            uniswapV2Router02.address
        );

        // Deploys exchange token
        // We replace the exchangeToken address in ccExchangeRequests
        const erc20Factory = new Erc20__factory(deployer);
        exchangeToken = await erc20Factory.deploy(
            "TestToken",
            "TT",
            100000
        );

        await exchangeToken.transfer(signer1.getAddress(), 10000)

        // Deploys an ERC20 token
        anotherExchangeToken = await erc20Factory.deploy(
            "AnotherTestToken",
            "ATT",
            100000
        );

        lockers = await deployLockers();

        // Deploys burn router

        const LockersManagerLogic = await deployments.getArtifact(
            "LockersManagerLogic"
        );
        mockLockers = await deployMockContract(
            deployer,
            LockersManagerLogic.abi
        )

        burnRouter = await deployBurnRouter();
        await burnRouter.initialize(
            1,
            mockBitcoinRelay.address,
            mockLockers.address,
            TREASURY,
            teleBTC.address,
            10,
            PROTOCOL_PERCENTAGE_FEE,
            10,
            10
        );

        await mockLockers.mock.burn
            .returns(10);
        await mockLockers.mock.isLocker
            .returns(true);
        await mockLockers.mock.getLockerTargetAddress
            .returns(LOCKER_TARGET_ADDRESS);
        await mockBitcoinRelay.mock.lastSubmittedHeight.returns(100);

        // Deploys ccExchangeRouter contract
        let linkLibraryAddresses: CcExchangeRouterLogicLibraryAddresses;

        let ccExchangeRouterLib = await deployCcExchangeRouterLib()
        linkLibraryAddresses = {
            "contracts/libraries/CcExchangeRouterLib.sol:CcExchangeRouterLib": ccExchangeRouterLib.address,
        };

        const ccExchangeRouterLogicFactory = new CcExchangeRouterLogic__factory(
            linkLibraryAddresses,
            deployer
        );
        const ccExchangeRouterLogic = await ccExchangeRouterLogicFactory.deploy();

        const ccExchangeRouterProxyFactory = new CcExchangeRouterProxy__factory(deployer);
        const ccExchangeRouterProxy = await ccExchangeRouterProxyFactory.deploy(
            ccExchangeRouterLogic.address,    
            proxyAdminAddress,
            "0x"
        );
        
        ccExchangeRouter = await ccExchangeRouterLogic.attach(
            ccExchangeRouterProxy.address
        );

        await ccExchangeRouter.initialize(
            STARTING_BLOCK_NUMBER,
            PROTOCOL_PERCENTAGE_FEE,
            CHAIN_ID,
            lockers.address,
            mockBitcoinRelay.address,
            teleBTC.address,
            TREASURY,
            mockAcross.address,
            burnRouter.address
        );

        // Sets exchangeConnector address in ccExchangeRouter
        await ccExchangeRouter.setExchangeConnector(APP_ID, exchangeConnector.address);

        await lockers.setTeleBTC(teleBTC.address)
        await lockers.addMinter(ccExchangeRouter.address)

        await teleBTC.addMinter(lockers.address)
        await teleBTC.addBurner(lockers.address)

        await ccExchangeRouter.setLockers(lockers.address)
        // await ccExchangeRouter.setInstantRouter(mockInstantRouter.address)

        // set chain id mapping 
        await ccExchangeRouter.setChainIdMapping(1, 1, 1);
    });


    const deployBurnRouterLib = async (
        _signer?: Signer
    ): Promise<BurnRouterLib> => {
        const BurnRouterLibFactory = new BurnRouterLib__factory(
            _signer || deployer
        );

        const burnRouterLib = await BurnRouterLibFactory.deploy(
        );

        return burnRouterLib;
    };

    const deployBurnRouter = async (
        _signer?: Signer
    ): Promise<Contract> => {
        burnRouterLib = await deployBurnRouterLib()
        let linkLibraryAddresses: BurnRouterLogicLibraryAddresses;

        linkLibraryAddresses = {
            "contracts/libraries/BurnRouterLib.sol:BurnRouterLib": burnRouterLib.address,
        };

        // Deploys lockers logic
        const burnRouterLogicFactory = new BurnRouterLogic__factory(
            linkLibraryAddresses,
            _signer || deployer
        );

        const burnRouterLogic = await burnRouterLogicFactory.deploy();

        // Deploys lockers proxy
        const burnRouterProxyFactory = new BurnRouterProxy__factory(
            _signer || deployer
        );
        const burnRouterProxy = await burnRouterProxyFactory.deploy(
            burnRouterLogic.address,
            proxyAdminAddress,
            "0x"
        )

        return await burnRouterLogic.attach(
            burnRouterProxy.address
        );

    };

    const deployTeleportDAOToken = async (
        _signer?: Signer
    ): Promise<ERC20> => {
        const erc20Factory = new Erc20__factory(
            _signer || deployer
        );

        const teleportDAOToken = await erc20Factory.deploy(
            "TeleportDAOToken",
            "TDT",
            telePortTokenInitialSupply
        );

        return teleportDAOToken;
    };

    const deployLockersManagerLib = async (
        _signer?: Signer
    ): Promise<LockersManagerLib> => {
        const LockersManagerLibFactory = new LockersManagerLib__factory(
            _signer || deployer
        );

        const lockersLib = await LockersManagerLibFactory.deploy(
        );

        return lockersLib;
    };

    const deployCcExchangeRouterLib = async (
        _signer?: Signer
    ): Promise<LockersManagerLib> => {
        const CcExchangeRouterFactory = new CcExchangeRouterLib__factory(
            _signer || deployer
        );

        const CcExchangeRouter = await CcExchangeRouterFactory.deploy(
        );

        return CcExchangeRouter;
    };

    const deployLockers = async (
        _signer?: Signer
    ): Promise<Contract> => {

        lockersLib = await deployLockersManagerLib()

        let linkLibraryAddresses: LockersManagerLogicLibraryAddresses;

        linkLibraryAddresses = {
            "contracts/libraries/LockersManagerLib.sol:LockersManagerLib": lockersLib.address,
        };

        // Deploys lockers logic
        const LockersManagerLogicFactory = new LockersManagerLogic__factory(
            linkLibraryAddresses,
            _signer || deployer
        );

        const LockersManagerLogic = await LockersManagerLogicFactory.deploy();

        // Deploys lockers proxy
        const lockersProxyFactory = new LockersManagerProxy__factory(
            _signer || deployer
        );
        const lockersProxy = await lockersProxyFactory.deploy(
            LockersManagerLogic.address,
            proxyAdminAddress,
            "0x"
        )

        const lockers = await LockersManagerLogic.attach(
            lockersProxy.address
        );

        // Initializes lockers proxy
        await lockers.initialize(
            teleBTC.address,
            mockPriceOracle.address,
            ONE_ADDRESS,
            0,
            minRequiredTNTLockedAmount,
            collateralRatio,
            liquidationRatio,
            LOCKER_PERCENTAGE_FEE,
            PRICE_WITH_DISCOUNT_RATIO
        )

        await lockers.setTST(teleportDAOToken.address)
        return lockers;
    };

    async function addLockerToLockers(): Promise<void> {
        // TODO change locker to target locker
        let lockerlocker = lockers.connect(locker)

        await lockerlocker.requestToBecomeLocker(
            LOCKER1_LOCKING_SCRIPT,
            0,
            minRequiredTNTLockedAmount,
            LOCKER_RESCUE_SCRIPT_P2PKH_TYPE,
            LOCKER_RESCUE_SCRIPT_P2PKH,
            {value: minRequiredTNTLockedAmount}
        )

        await lockers.addLocker(lockerAddress)
    }

    describe("#ccExchange", async () => {
        let oldReserveTeleBTC: BigNumber;
        let oldReserveTT: BigNumber;
        let oldDeployerBalanceTeleBTC: BigNumber;
        let oldUserBalanceTeleBTC: BigNumber;
        let oldDeployerBalanceTT: BigNumber;
        let oldUserBalanceTT: BigNumber;
        let oldTotalSupplyTeleBTC: BigNumber;

        function calculateFees(request: any): [number, number, number] {
            // Calculates fees
            let lockerFee = Math.floor(
                request.bitcoinAmount*LOCKER_PERCENTAGE_FEE/10000
            );
            let teleporterFee = request.teleporterFee
            let protocolFee = Math.floor(
                request.bitcoinAmount*PROTOCOL_PERCENTAGE_FEE/10000
            );

            return[lockerFee, teleporterFee, protocolFee]
        }

        async function checksWhenExchangeSucceed(
            _exchangeToken: any,
            isFixedToken: boolean,
            recipientAddress: string,
            bitcoinAmount: number,
            teleporterFee: number,
            protocolFee: number,
            lockerFee: number,
            expectedOutputAmount: number,
            requiredInputAmount?: number
        ) {
            // General checks

            // Records new supply of teleBTC
            let newTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Records new teleBTC and TT balances of user
            let newUserBalanceTeleBTC = await teleBTC.balanceOf(
                recipientAddress
            );
            let newUserBalanceTT = await _exchangeToken.balanceOf(
                recipientAddress
            );

            // Records new teleBTC and TDT balances of teleporter
            let newDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            let newDeployerBalanceTT = await _exchangeToken.balanceOf(deployerAddress);

            // Checks that extra teleBTC hasn't been minted
            await expect(newTotalSupplyTeleBTC).to.equal(
                oldTotalSupplyTeleBTC.add(bitcoinAmount)
            );

            // Checks that enough teleBTC has been minted for teleporter
            await expect(newDeployerBalanceTeleBTC).to.equal(
                oldDeployerBalanceTeleBTC.add(teleporterFee)
            );
            
            // Checks that teleporter TT balance hasn't changed
            await expect(newDeployerBalanceTT).to.equal(
                oldDeployerBalanceTT
            );

            // Checks that correct amount of teleBTC has been minted for protocol
            await expect(
                await teleBTC.balanceOf(TREASURY)
            ).to.equal(protocolFee);

            // Checks that correct amount of teleBTC has been minted for locker
            await expect(
                await teleBTC.balanceOf(lockerAddress)
            ).to.equal(lockerFee);

            // Checks that user received enough TT
            await expect(newUserBalanceTT).to.equal(
                oldUserBalanceTT.add(expectedOutputAmount)
            );

            if (isFixedToken == true) {
                // Checks that user teleBTC balance hasn't changed
                await expect(newUserBalanceTeleBTC).to.equal(
                    oldUserBalanceTeleBTC
                );
            } else {
                // Checks that user received unused teleBTC
                if (requiredInputAmount != undefined) {
                    await expect(newUserBalanceTeleBTC).to.equal(
                        oldUserBalanceTeleBTC.toNumber() +
                        bitcoinAmount -
                        teleporterFee -
                        lockerFee -
                        protocolFee -
                        requiredInputAmount
                    );
                }
            }
        }

        async function checksWhenExchangeFails(
            recipientAddress: string,
            bitcoinAmount: number,
            teleporterFee: number,
            protocolFee: number,
            lockerFee: number
        ) {
            // Records new supply of teleBTC
            let newTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Records new teleBTC and TDT balances of user
            let newUserBalanceTeleBTC = await teleBTC.balanceOf(
                recipientAddress
            );
            let newUserBalanceTT = await exchangeToken.balanceOf(
                recipientAddress
            );

            // Records new teleBTC and TDT balances of teleporter
            let newDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            let newDeployerBalanceTT = await exchangeToken.balanceOf(deployerAddress);

            // Checks enough teleBTC has been minted for user
            await expect(newUserBalanceTeleBTC).to.equal(
                oldUserBalanceTeleBTC.add(
                    bitcoinAmount - lockerFee - teleporterFee - protocolFee
                )
            );

            // Checks that enough teleBTC has been minted for teleporter
            await expect(newDeployerBalanceTeleBTC).to.equal(
                oldDeployerBalanceTeleBTC.add(teleporterFee)
            );

            // Checks that user TT balance hasn't changed
            await expect(newUserBalanceTT).to.equal(
                oldUserBalanceTT
            );

            // Checks that correct amount of teleBTC has been minted for protocol
            await expect(
                await teleBTC.balanceOf(TREASURY)
            ).to.equal(protocolFee);

            // Checks that correct amount of teleBTC has been minted for locker
            await expect(
                await teleBTC.balanceOf(lockerAddress)
            ).to.equal(lockerFee);

            // Checks extra teleBTC hasn't been minted
            await expect(newTotalSupplyTeleBTC).to.equal(
                oldTotalSupplyTeleBTC.add(bitcoinAmount)
            );
        }

        beforeEach("Adds liquidity to liquidity pool", async () => {
            // Takes snapshot before adding liquidity
            snapshotId = await takeSnapshot(deployer.provider);

            // Adds liquidity to teleBTC-TDT liquidity pool
            await teleBTC.addMinter(deployerAddress)
            await teleBTC.mint(deployerAddress, 10000000);
            await teleBTC.approve(uniswapV2Router02.address, 10000);
            await exchangeToken.approve(uniswapV2Router02.address, 10000);
            let addedLiquidityA = 10000;
            let addedLiquidityB = 10000;
            
            // console.log(uniswapV2Router02)
            // await uniswapV2Factory.createPair(teleBTC.address, exchangeToken.address);

            await uniswapV2Router02.addLiquidity(
                teleBTC.address,
                exchangeToken.address,
                addedLiquidityA,
                addedLiquidityB,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                1000000000000000, // Long deadline
            );

            // Creates liquidity pool of TeleBTC-WETH and adds liquidity in it
            await teleBTC.approve(uniswapV2Router02.address, 10000);
            await uniswapV2Router02.addLiquidityETH(
                teleBTC.address,
                10000,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                10000000000000, // Long deadline
                {value: 10000}
            );


            let liquidityPoolAddress = await uniswapV2Factory.getPair(
                teleBTC.address,
                exchangeToken.address
            );

            // Records total supply of teleBTC
            oldTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Loads teleBTC-TDT liquidity pool
            uniswapV2Pair = await uniswapV2Pair__factory.attach(liquidityPoolAddress);
            // Records current reserves of teleBTC and TT
            if (await uniswapV2Pair.token0() == teleBTC.address) {
                [oldReserveTeleBTC, oldReserveTT] = await uniswapV2Pair.getReserves();
            } else {
                [oldReserveTT, oldReserveTeleBTC] = await uniswapV2Pair.getReserves()
            }

            // Records current teleBTC and TT balances of user and teleporter
            oldUserBalanceTeleBTC = await teleBTC.balanceOf(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress
            );
            oldDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            oldUserBalanceTT = await exchangeToken.balanceOf(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress
            );
            oldDeployerBalanceTT = await exchangeToken.balanceOf(deployerAddress);

            
            await ccExchangeRouter.setInstantRouter(deployerAddress)
            await addLockerToLockers();
        });

        afterEach(async () => {
            // Reverts the state to the before of adding liquidity
            await revertProvider(deployer.provider, snapshotId);
        });

        it("Exchanges teleBTC for desired exchange token (fixed token = input)", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );
            
            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))
            await expect(
                ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            )
            .to.emit(ccExchangeRouter, 'NewWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    expectedOutputAmount
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            );
            
            await checksWhenExchangeSucceed(
                exchangeToken,
                true,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount,
                teleporterFee,
                protocolFee,
                lockerFee,
                expectedOutputAmount.toNumber()
            );
        })

        it("only owner can wrap and swap", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );
            
            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))
            await expect(
                ccExchangeRouter.connect(signer1).wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.be.revertedWith("ExchangeRouter: invalid sender")
        })

        it("revert since bridge fee is not zero but destination chain is equal to middle chain", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            vout = vout.replace(11000000, 11111111)
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );
            
            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))
            await expect(
                ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.be.revertedWith("ExchangeRouter: invalid brdige fee")
        })

        // it.only("revert since path[0] is not telebtc", async function () {
        //     // Replaces dummy address in vout with exchange token address
        //     let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
        //     vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

        //     await expect(
        //         ccExchangeRouter.wrapAndSwap(
        //             {
        //                 version: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
        //                 vin: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
        //                 vout,
        //                 locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
        //                 blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
        //                 intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
        //                 index: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
        //             },
        //             LOCKER1_LOCKING_SCRIPT,
        //             [ONE_ADDRESS, exchangeToken.address]
        //         )
        //     ).to.be.revertedWith("CcExchangeRouter: invalid path")
        // })

        // it.only("revert since path[path.length - 1] is not desired token", async function () {
        //     // Replaces dummy address in vout with exchange token address
        //     let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
        //     vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

        //     await expect(
        //         ccExchangeRouter.wrapAndSwap(
        //             {
        //                 version: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
        //                 vin: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
        //                 vout,
        //                 locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
        //                 blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
        //                 intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
        //                 index: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
        //             },
        //             LOCKER1_LOCKING_SCRIPT,
        //             [teleBTC.address, ONE_ADDRESS]
        //         )
        //     ).to.be.revertedWith("CcExchangeRouter: invalid path")
        // })

        it("Exchanges teleBTC for desired exchange token through wrapped native token", async function () {
            // Replaces dummy address in vout with another exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(
                DUMMY_ADDRESS,
                exchangeToken.address.slice(2, exchangeToken.address.length)
            );

            // Creates liquidity pool of WETH-ATT and adds liquidity in it
            await exchangeToken.connect(signer1).approve(uniswapV2Router02.address, 10000);
            await uniswapV2Router02.connect(signer1).addLiquidityETH(
                exchangeToken.address,
                10000,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                10000000000000, // Long deadline
                {value: 10000}
            );

            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            let expectedOutputAmount = await uniswapV2Router02.getAmountsOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                [teleBTC.address, weth.address, exchangeToken.address]
            );

            // Exchanges teleBTC for ATT
            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, weth.address, exchangeToken.address]
                )
            ).to.emit(ccExchangeRouter, 'NewWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    expectedOutputAmount[expectedOutputAmount.length - 1]
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            );;

            await checksWhenExchangeSucceed(
                exchangeToken,
                true,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount,
                teleporterFee,
                protocolFee,
                lockerFee,
                expectedOutputAmount[expectedOutputAmount.length - 1].toNumber()
            );
        })

        it("Mints teleBTC since slippage is high (output amount < expected output amount)", async function () {
            // note: isFixedToken = true (input is fixed)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage
            );

            // Mints teleBTC
            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.emit(ccExchangeRouter, 'FailedWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    0
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            ).and.not.emit(ccExchangeRouter, 'NewWrapAndSwap');

            // Checks needed conditions when exchange fails
            await checksWhenExchangeFails(
                CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.recipientAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_highSlippage.bitcoinAmount,
                teleporterFee,
                protocolFee,
                lockerFee
            );
        })

        it("Mints teleBTC since exchange token doesn't exist", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, ONE_ADDRESS.slice(2, ONE_ADDRESS.length));

            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput
            );

            let txId = "0xaf06a4c79ff960714920b3ea0c8bdda435073165b89b89bd3591f0997b2d95b3"
            // Mints teleBTC
            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, ONE_ADDRESS]
                )
            ).to.emit(ccExchangeRouter, 'FailedWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                [teleBTC.address, ONE_ADDRESS],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    0
                ],
                0,
                deployerAddress,
                txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            )

            // Checks needed conditions when exchange fails
            await checksWhenExchangeFails(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount,
                teleporterFee,
                protocolFee,
                lockerFee
            );
        })

        it("Mints teleBTC since exchange token is zero", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, ZERO_ADDRESS.slice(2, ZERO_ADDRESS.length));

            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput
            );

            // Mints teleBTC
            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index,
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, ZERO_ADDRESS]
                )
            ).to.emit(ccExchangeRouter, 'FailedWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                [teleBTC.address, ZERO_ADDRESS],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    0
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            ).and.not.emit(ccExchangeRouter, 'NewWrapAndSwap');

            // Checks needed conditions when exchange fails
            await checksWhenExchangeFails(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.bitcoinAmount,
                teleporterFee,
                protocolFee,
                lockerFee
            );
        })

        it("Reverts since given appId doesn't exist", async function () {

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidAppId.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouter: invalid appId");
        })

        it("Reverts if user hasn't sent BTC to locker", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouterLib: zero input");
        })

        it("Reverts if locker doesn't exist", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.index,
                    ],
                    CC_EXCHANGE_REQUESTS.normalCCExchange_wrongLocker.desiredRecipient,
                    [teleBTC.address, ZERO_ADDRESS]
                )
            ).to.revertedWith("ExchangeRouter: not locker");
        })

        it("Reverts if the percentage fee is out of range [0,10000)", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidFee.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouterLib: wrong fee");
        })

        it("Reverts if the request belongs to wrong chain", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_invalidChainId.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouter: wrong chain");
        })
        
        it("Reverts if the request speed is not 0, (used for filler)", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_wrongSpeed.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouterLib: filler is not supported");
        })

        it("Reverts since request belongs to an old block header", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        STARTING_BLOCK_NUMBER - 1,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouter: old request");
        })

        it("Reverts since lock time is non-zero", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        '0x11111111',
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouter: non-zero locktime");
        })

        it("Reverts if request has not been finalized yet", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await mockBitcoinRelay.mock.checkTxProof.returns(false);

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouter: not finalized");
        })

        it("Reverts if paid fee is not sufficient", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            await mockBitcoinRelay.mock.getBlockHeaderFee.returns(1);

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouterLib: low fee");
        })
    });

    describe("#isRequestUsed", async () => {

        beforeEach(async () => {
            snapshotId = await takeSnapshot(signer1.provider);
            await ccExchangeRouter.setInstantRouter(deployerAddress)
            await addLockerToLockers();
        });

        afterEach(async () => {
            await revertProvider(signer1.provider, snapshotId);
        });

        it("Checks if the request has been used before (unused)", async function () {
            expect(
                await ccExchangeRouter.isRequestUsed(CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId)
            ).to.equal(false);
        })

        it("Reverts since the request has been executed before", async function () {

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            let tx = await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]

            );

            await expect(
                ccExchangeRouter.wrapAndSwap(
                    [
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.version,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.vin,
                        vout,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.locktime,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.blockNumber,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.intermediateNodes,
                        CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.index
                    ],
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.revertedWith("ExchangeRouterLib: already used");
        })

        expect(
            await ccExchangeRouter.isRequestUsed(CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId)
        ).to.equal(true);

    });

    describe("#setters", async () => {

        beforeEach(async () => {
            snapshotId = await takeSnapshot(signer1.provider);
        });

        afterEach(async () => {
            await revertProvider(signer1.provider, snapshotId);
        });

        it("Sets protocol percentage fee", async function () {
            await expect(
                ccExchangeRouter.setProtocolPercentageFee(100)
            ).to.emit(
                ccExchangeRouter, "NewProtocolPercentageFee"
            ).withArgs(PROTOCOL_PERCENTAGE_FEE, 100);

            expect(
                await ccExchangeRouter.protocolPercentageFee()
            ).to.equal(100);
        })

        it("Sets third party fee and address", async function () {
            await expect(
                await ccExchangeRouter.setThirdPartyFee(1, 100)
            ).to.emit(
                ccExchangeRouter, "NewThirdPartyFee"
            ).withArgs(1, 0, 100);

            await expect(
                ccExchangeRouter.connect(signer1).setThirdPartyFee(1, 100)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                await ccExchangeRouter.thirdPartyFee(1)
            ).to.be.equal(100)

            await expect(
                ccExchangeRouter.setThirdPartyAddress(1, ONE_ADDRESS)
            ).to.emit(
                ccExchangeRouter, "NewThirdPartyAddress"
            ).withArgs(1, ZERO_ADDRESS, ONE_ADDRESS);

            await expect(
                ccExchangeRouter.connect(signer1).setThirdPartyAddress(1, ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                await ccExchangeRouter.thirdPartyAddress(1)
            ).to.be.equal(ONE_ADDRESS)
        })

        it("Reverts since protocol percentage fee is greater than 10000", async function () {
            await expect(
                ccExchangeRouter.setProtocolPercentageFee(10001)
            ).to.revertedWith("CCExchangeRouter: fee is out of range");
        })

        it("Sets relay, lockers, instant router, teleBTC and treasury", async function () {
            await expect(
                await ccExchangeRouter.setRelay(ONE_ADDRESS)
            ).to.emit(
                ccExchangeRouter, "NewRelay"
            ).withArgs(mockBitcoinRelay.address, ONE_ADDRESS);


            await expect(
                await ccExchangeRouter.relay()
            ).to.equal(ONE_ADDRESS);

            await expect(
                await ccExchangeRouter.setLockers(ONE_ADDRESS)
            ).to.emit(
                ccExchangeRouter, "NewLockers"
            ).withArgs(lockers.address, ONE_ADDRESS);

            await expect(
                await ccExchangeRouter.lockers()
            ).to.equal(ONE_ADDRESS);

            await expect(
                ccExchangeRouter.setInstantRouter(ONE_ADDRESS)
            ).to.emit(
                ccExchangeRouter, "NewInstantRouter"
            ).withArgs(ZERO_ADDRESS, ONE_ADDRESS);

            await expect(
                await ccExchangeRouter.instantRouter()
            ).to.equal(ONE_ADDRESS);

            await expect(
                await ccExchangeRouter.setTeleBTC(ONE_ADDRESS)
            ).to.emit(
                ccExchangeRouter, "NewTeleBTC"
            ).withArgs(teleBTC.address, ONE_ADDRESS);


            await expect(
                await ccExchangeRouter.teleBTC()
            ).to.equal(ONE_ADDRESS);

            await expect(
                await ccExchangeRouter.setTreasury(ONE_ADDRESS)
            ).to.emit(
                ccExchangeRouter, "NewTreasury"
            ).withArgs(TREASURY, ONE_ADDRESS);


            await expect(
                await ccExchangeRouter.treasury()
            ).to.equal(ONE_ADDRESS);

        })

        it("Reverts since given address is zero", async function () {
            await expect(
                ccExchangeRouter.setRelay(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");

            await expect(
                ccExchangeRouter.setLockers(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");

            await expect(
                ccExchangeRouter.setInstantRouter(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");

            await expect(
                ccExchangeRouter.setTeleBTC(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");

            await expect(
                ccExchangeRouter.setTreasury(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");

            await expect(
                ccExchangeRouter.setBurnRouter(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");

            await expect(
                ccExchangeRouter.setAcross(ZERO_ADDRESS)
            ).to.revertedWith("ZeroAddress()");
        })

        it("Reverts since new starting block number is less than what is set before", async function () {
            await expect(
                ccExchangeRouter.setStartingBlockNumber(STARTING_BLOCK_NUMBER - 1)
            ).to.revertedWith("CCExchangeRouter: low startingBlockNumber");
        })

        it("can set setWrappedNativeToken", async function () {
            await ccExchangeRouter.setWrappedNativeToken(ONE_ADDRESS)

            await expect(
                await ccExchangeRouter.wrappedNativeToken()
            ).to.equal(ONE_ADDRESS);
        })

        it("can supportChain and removeChain", async function () {
            await ccExchangeRouter.supportChain(1)

            await expect(
                await ccExchangeRouter.isChainSupported(1)
            ).to.equal(true);

            await ccExchangeRouter.removeChain(1)

            await expect(
                await ccExchangeRouter.isChainSupported(1)
            ).to.equal(false);
        })


        it("only owner can set", async function () {
            await expect(
                ccExchangeRouter.connect(signer1).removeChain(2)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).supportChain(2)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).removeToken(2, ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).supportToken(2, ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setChainIdMapping(2, 2, 2)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setWrappedNativeToken(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setAcross(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setBurnRouter(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setStartingBlockNumber(1)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setRelay(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setInstantRouter(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setLockers(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setExchangeConnector(1, ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setTeleBTC(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setProtocolPercentageFee(10)
            ).to.be.revertedWith("Ownable: caller is not the owner")

            await expect(
                ccExchangeRouter.connect(signer1).setTreasury(ONE_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")
        })

    });

    describe("#renounce ownership", async () => {
        it("owner can't renounce ownership", async function () {
            await ccExchangeRouter.renounceOwnership()
            await expect(
                await ccExchangeRouter.owner()
            ).to.equal(deployerAddress);
        })
    });

    describe("#Across", async () => {
        let oldReserveTeleBTC: BigNumber;
        let oldReserveTT: BigNumber;
        let oldDeployerBalanceTeleBTC: BigNumber;
        let oldUserBalanceTeleBTC: BigNumber;
        let oldDeployerBalanceTT: BigNumber;
        let oldUserBalanceTT: BigNumber;
        let oldTotalSupplyTeleBTC: BigNumber;

        function calculateFees(request: any): [number, number, number] {
            // Calculates fees
            let lockerFee = Math.floor(
                request.bitcoinAmount*LOCKER_PERCENTAGE_FEE/10000
            );
            let teleporterFee = request.teleporterFee
            let protocolFee = Math.floor(
                request.bitcoinAmount*PROTOCOL_PERCENTAGE_FEE/10000
            );

            return[lockerFee, teleporterFee, protocolFee]
        }

        async function checksWhenExchangeSucceed(
            _exchangeToken: any,
            isFixedToken: boolean,
            recipientAddress: string,
            bitcoinAmount: number,
            teleporterFee: number,
            protocolFee: number,
            lockerFee: number,
            expectedOutputAmount: number,
            requiredInputAmount?: number
        ) {
            // General checks

            // Records new supply of teleBTC
            let newTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Records new teleBTC and TT balances of user
            let newUserBalanceTeleBTC = await teleBTC.balanceOf(
                recipientAddress
            );
            let newUserBalanceTT = await _exchangeToken.balanceOf(
                recipientAddress
            );

            // Records new teleBTC and TDT balances of teleporter
            let newDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            let newDeployerBalanceTT = await _exchangeToken.balanceOf(deployerAddress);

            // Checks that extra teleBTC hasn't been minted
            await expect(newTotalSupplyTeleBTC).to.equal(
                oldTotalSupplyTeleBTC.add(bitcoinAmount)
            );

            // Checks that enough teleBTC has been minted for teleporter
            await expect(newDeployerBalanceTeleBTC).to.equal(
                oldDeployerBalanceTeleBTC.add(teleporterFee)
            );
            
            // Checks that teleporter TT balance hasn't changed
            await expect(newDeployerBalanceTT).to.equal(
                oldDeployerBalanceTT
            );

            // Checks that correct amount of teleBTC has been minted for protocol
            await expect(
                await teleBTC.balanceOf(TREASURY)
            ).to.equal(protocolFee);

            // Checks that correct amount of teleBTC has been minted for locker
            await expect(
                await teleBTC.balanceOf(lockerAddress)
            ).to.equal(lockerFee);

            // TOOD change receiver address 
            // // Checks that user received enough TT
            // await expect(newUserBalanceTT).to.equal(
            //     oldUserBalanceTT.add(expectedOutputAmount)
            // );

            if (isFixedToken == true) {
                // Checks that user teleBTC balance hasn't changed
                await expect(newUserBalanceTeleBTC).to.equal(
                    oldUserBalanceTeleBTC
                );
            } else {
                // Checks that user received unused teleBTC
                if (requiredInputAmount != undefined) {
                    await expect(newUserBalanceTeleBTC).to.equal(
                        oldUserBalanceTeleBTC.toNumber() +
                        bitcoinAmount -
                        teleporterFee -
                        lockerFee -
                        protocolFee -
                        requiredInputAmount
                    );
                }
            }
        }

        async function checksWhenExchangeFails(
            recipientAddress: string,
            bitcoinAmount: number,
            teleporterFee: number,
            protocolFee: number,
            lockerFee: number
        ) {
            // Records new supply of teleBTC
            let newTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Records new teleBTC and TDT balances of user
            let newUserBalanceTeleBTC = await teleBTC.balanceOf(
                recipientAddress
            );
            let newUserBalanceTT = await exchangeToken.balanceOf(
                recipientAddress
            );

            // Records new teleBTC and TDT balances of teleporter
            let newDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            let newDeployerBalanceTT = await exchangeToken.balanceOf(deployerAddress);

            // Checks enough teleBTC has been minted for user
            await expect(newUserBalanceTeleBTC).to.equal(
                oldUserBalanceTeleBTC.add(
                    bitcoinAmount - lockerFee - teleporterFee - protocolFee
                )
            );

            // Checks that enough teleBTC has been minted for teleporter
            await expect(newDeployerBalanceTeleBTC).to.equal(
                oldDeployerBalanceTeleBTC.add(teleporterFee)
            );

            // Checks that user TT balance hasn't changed
            await expect(newUserBalanceTT).to.equal(
                oldUserBalanceTT
            );

            // Checks that correct amount of teleBTC has been minted for protocol
            await expect(
                await teleBTC.balanceOf(TREASURY)
            ).to.equal(protocolFee);

            // Checks that correct amount of teleBTC has been minted for locker
            await expect(
                await teleBTC.balanceOf(lockerAddress)
            ).to.equal(lockerFee);

            // Checks extra teleBTC hasn't been minted
            await expect(newTotalSupplyTeleBTC).to.equal(
                oldTotalSupplyTeleBTC.add(bitcoinAmount)
            );
        }

        const parseSignatureToRSV = (signatureHex: string) => {
            // Ensure the hex string starts with '0x'
            if (!signatureHex.startsWith('0x')) {
              throw new Error('Signature must start with 0x')
            }
          
            // Convert the hex string to a Buffer
            const signatureBuffer = Buffer.from(signatureHex.slice(2), 'hex')
          
            // Check the length of the signature (should be 65 bytes)
            if (signatureBuffer.length !== 65) {
              throw new Error('Invalid signature length')
            }
          
            // Extract r, s, and v from the signature
            const r = `0x${signatureBuffer.subarray(0, 32).toString('hex')}`
            const s = `0x${signatureBuffer.subarray(32, 64).toString('hex')}`
            const v = signatureBuffer[64]
          
            return { r, s, v }
          }

        beforeEach(async () => {
            snapshotId = await takeSnapshot(signer1.provider);
            // Adds liquidity to teleBTC-TDT liquidity pool
            await teleBTC.addMinter(deployerAddress)
            await teleBTC.mint(deployerAddress, 10000000);
            await teleBTC.approve(uniswapV2Router02.address, 10000);
            await exchangeToken.approve(uniswapV2Router02.address, 10000);
            let addedLiquidityA = 10000;
            let addedLiquidityB = 10000;
            
            // console.log(uniswapV2Router02)
            // await uniswapV2Factory.createPair(teleBTC.address, exchangeToken.address);

            await uniswapV2Router02.addLiquidity(
                teleBTC.address,
                exchangeToken.address,
                addedLiquidityA,
                addedLiquidityB,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                1000000000000000, // Long deadline
            );

            // Creates liquidity pool of TeleBTC-WETH and adds liquidity in it
            await teleBTC.approve(uniswapV2Router02.address, 10000);
            await uniswapV2Router02.addLiquidityETH(
                teleBTC.address,
                10000,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                10000000000000, // Long deadline
                {value: 10000}
            );


            let liquidityPoolAddress = await uniswapV2Factory.getPair(
                teleBTC.address,
                exchangeToken.address
            );
            
            // Records total supply of teleBTC
            oldTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Loads teleBTC-TDT liquidity pool
            uniswapV2Pair = await uniswapV2Pair__factory.attach(liquidityPoolAddress);
            // Records current reserves of teleBTC and TT
            if (await uniswapV2Pair.token0() == teleBTC.address) {
                [oldReserveTeleBTC, oldReserveTT] = await uniswapV2Pair.getReserves();
            } else {
                [oldReserveTT, oldReserveTeleBTC] = await uniswapV2Pair.getReserves()
            }

            // Records current teleBTC and TT balances of user and teleporter
            oldUserBalanceTeleBTC = await teleBTC.balanceOf(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress
            );
            oldDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            oldUserBalanceTT = await exchangeToken.balanceOf(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress
            );
            oldDeployerBalanceTT = await exchangeToken.balanceOf(deployerAddress);

            await ccExchangeRouter.setInstantRouter(deployerAddress)

            await addLockerToLockers();
            await ccExchangeRouter.setChainIdMapping(2, 1, 2);
            await ccExchangeRouter.supportChain(2);
            await ccExchangeRouter.supportToken(2, exchangeToken.address);

        });

        afterEach(async () => {
            await revertProvider(signer1.provider, snapshotId);
        });

        it("send token to other chain using across", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            let bridgeFee = expectedOutputAmount.mul(CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.acrossFee).div(10 ** 7)
            
            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))

            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            )
            .to.emit(ccExchangeRouter, 'NewWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    expectedOutputAmount - bridgeFee
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, bridgeFee],
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.chainId

            );
            
            await checksWhenExchangeSucceed(
                exchangeToken,
                true,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.recipientAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount,
                teleporterFee,
                protocolFee,
                lockerFee,
                expectedOutputAmount.toNumber() - bridgeFee.toNumber()
            );
        })

        it("send token to other chain failed because chain is not supported", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));

            ccExchangeRouter.removeChain(2)
            await expect(
                ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.be.revertedWith("ExchangeRouter: invalid chain id")
        })
        
        it("swap fails", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );
            
            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))

            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            ).to.emit(ccExchangeRouter, 'FailedWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                    0
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.appId,
                0,
                [teleporterFee, lockerFee, protocolFee, 0, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.chainId
            )
        })

        it("can burn telebtc if swap failed", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint8', 
                'bytes',
                'uint'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                USER_SCRIPT_P2PKH_TYPE,
                USER_SCRIPT_P2PKH,
                10
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                let signature
                let rsv
                signature = await signer1.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
            
                await expect(
                    await ccExchangeRouter.withdrawFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v,
                        LOCKER1_LOCKING_SCRIPT
                    )
                ).to.emit(burnRouter, "NewUnwrap")
            }
        })

        it("can't burn telebtc because of wrong sig", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint8', 
                'bytes',
                'uint'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.txId,
                USER_SCRIPT_P2PKH_TYPE,
                USER_SCRIPT_P2PKH,
                10
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                let signature
                let rsv
                signature = await signer1.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
            
                await expect(
                    ccExchangeRouter.withdrawFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v,
                        LOCKER1_LOCKING_SCRIPT
                    )
                ).to.be.revertedWith("ExchangeRouter: invalid signer")
            }
        })

        it("can't burn telebtc twice", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint8', 
                'bytes',
                'uint'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                USER_SCRIPT_P2PKH_TYPE,
                USER_SCRIPT_P2PKH,
                10
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                let signature
                let rsv
                signature = await signer1.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
            
                await ccExchangeRouter.withdrawFailedWrapAndSwap(
                    withdrawMessage,
                    rsv.r,
                    rsv.s,
                    rsv.v,
                    LOCKER1_LOCKING_SCRIPT
                )

                await expect(
                    ccExchangeRouter.withdrawFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v,
                        LOCKER1_LOCKING_SCRIPT
                    )
                ).to.be.revertedWith("ExchangeRouter: already processed")
            }
        })

        it("can retry failed cc exchange if swap failed", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint',
                'uint',
                'address[]',
                'bytes'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                expectedOutputAmount,
                10,
                [teleBTC.address, exchangeToken.address],
                LOCKER1_LOCKING_SCRIPT
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                await ccExchangeRouter.supportToken(2, exchangeToken.address)

                let signature
                let rsv
                signature = await signer1.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
                await expect(
                    await ccExchangeRouter.retryFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v
                    )
                )
            }
        })

        it("can't retry failed cc exchange if swap fail again", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint',
                'uint',
                'address[]',
                'bytes'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                expectedOutputAmount,
                10,
                [teleBTC.address, exchangeToken.address],
                LOCKER1_LOCKING_SCRIPT
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                let signature
                let rsv
                signature = await signer1.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
                await expect(
                    ccExchangeRouter.retryFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v
                    )
                ).to.be.revertedWith("ExchangeRouter: swap failed")
            }
        })

        it("can't retry because of wrong sig", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint',
                'uint',
                'address[]',
                'bytes'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                expectedOutputAmount,
                20,
                [teleBTC.address, exchangeToken.address],
                LOCKER1_LOCKING_SCRIPT
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                await ccExchangeRouter.supportToken(2, exchangeToken.address)

                let signature
                let rsv
                signature = await deployer.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
                await expect(
                    ccExchangeRouter.retryFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v
                    )
                ).to.be.revertedWith("ExchangeRouter: invalid signer")
            }
        })

        it("can't retry twice", async function () {
            // fail swap
            await ccExchangeRouter.removeToken(2, exchangeToken.address)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.bitcoinAmount - teleporterFee - lockerFee - protocolFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await ccExchangeRouter.wrapAndSwap(
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.version,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.vin,
                    vout,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.locktime,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.blockNumber,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.intermediateNodes,
                    CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.index
                ],
                LOCKER1_LOCKING_SCRIPT,
                [teleBTC.address, exchangeToken.address]
            )

            let withdrawMessage = abiUtils.encodeParameters([
                'bytes32',
                'uint',
                'uint',
                'address[]',
                'bytes'
            ], [
                CC_EXCHANGE_REQUESTS.normalCCExchangeToOtherChain_fixedInput.txId,
                expectedOutputAmount,
                10,
                [teleBTC.address, exchangeToken.address],
                LOCKER1_LOCKING_SCRIPT
            ])
            
            let messageHex = await web3.utils.soliditySha3(
                {
                    type: 'bytes',
                    value: withdrawMessage
                }
            )

            if (messageHex != null) {
                await ccExchangeRouter.supportToken(2, exchangeToken.address)

                let signature
                let rsv
                signature = await signer1.signMessage(ethers.utils.arrayify(messageHex))
                rsv = await parseSignatureToRSV(signature) 
                await ccExchangeRouter.retryFailedWrapAndSwap(
                    withdrawMessage,
                    rsv.r,
                    rsv.s,
                    rsv.v
                )
                await expect(
                    ccExchangeRouter.retryFailedWrapAndSwap(
                        withdrawMessage,
                        rsv.r,
                        rsv.s,
                        rsv.v
                    )
                ).to.be.revertedWith("ExchangeRouter: already processed")
            }
        })

    });

    describe("#Third party", async () => {
        let oldReserveTeleBTC: BigNumber;
        let oldReserveTT: BigNumber;
        let oldDeployerBalanceTeleBTC: BigNumber;
        let oldUserBalanceTeleBTC: BigNumber;
        let oldDeployerBalanceTT: BigNumber;
        let oldUserBalanceTT: BigNumber;
        let oldTotalSupplyTeleBTC: BigNumber;

        function calculateFees(request: any): [number, number, number, number] {
            // Calculates fees
            let lockerFee = Math.floor(
                request.bitcoinAmount*LOCKER_PERCENTAGE_FEE/10000
            );
            let teleporterFee = request.teleporterFee
            let protocolFee = Math.floor(
                request.bitcoinAmount*PROTOCOL_PERCENTAGE_FEE/10000
            );
            let thirdPartyFee = Math.floor(
                request.bitcoinAmount*THIRD_PARTY_PERCENTAGE_FEE/10000
            );

            return[lockerFee, teleporterFee, protocolFee, thirdPartyFee]
        }

        async function checksWhenExchangeSucceed(
            _exchangeToken: any,
            isFixedToken: boolean,
            recipientAddress: string,
            bitcoinAmount: number,
            teleporterFee: number,
            protocolFee: number,
            lockerFee: number,
            expectedOutputAmount: number,
            requiredInputAmount?: number
        ) {
            // General checks

            // Records new supply of teleBTC
            let newTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Records new teleBTC and TT balances of user
            let newUserBalanceTeleBTC = await teleBTC.balanceOf(
                recipientAddress
            );
            let newUserBalanceTT = await _exchangeToken.balanceOf(
                recipientAddress
            );

            // Records new teleBTC and TDT balances of teleporter
            let newDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            let newDeployerBalanceTT = await _exchangeToken.balanceOf(deployerAddress);

            // Checks that extra teleBTC hasn't been minted
            await expect(newTotalSupplyTeleBTC).to.equal(
                oldTotalSupplyTeleBTC.add(bitcoinAmount)
            );

            // Checks that enough teleBTC has been minted for teleporter
            await expect(newDeployerBalanceTeleBTC).to.equal(
                oldDeployerBalanceTeleBTC.add(teleporterFee)
            );
            
            // Checks that teleporter TT balance hasn't changed
            await expect(newDeployerBalanceTT).to.equal(
                oldDeployerBalanceTT
            );

            // Checks that correct amount of teleBTC has been minted for protocol
            await expect(
                await teleBTC.balanceOf(TREASURY)
            ).to.equal(protocolFee);

            // Checks that correct amount of teleBTC has been minted for locker
            await expect(
                await teleBTC.balanceOf(lockerAddress)
            ).to.equal(lockerFee);

            // Checks that user received enough TT
            await expect(newUserBalanceTT).to.equal(
                oldUserBalanceTT.add(expectedOutputAmount)
            );

            if (isFixedToken == true) {
                // Checks that user teleBTC balance hasn't changed
                await expect(newUserBalanceTeleBTC).to.equal(
                    oldUserBalanceTeleBTC
                );
            } else {
                // Checks that user received unused teleBTC
                if (requiredInputAmount != undefined) {
                    await expect(newUserBalanceTeleBTC).to.equal(
                        oldUserBalanceTeleBTC.toNumber() +
                        bitcoinAmount -
                        teleporterFee -
                        lockerFee -
                        protocolFee -
                        requiredInputAmount
                    );
                }
            }
        }

        async function checksWhenExchangeFails(
            recipientAddress: string,
            bitcoinAmount: number,
            teleporterFee: number,
            protocolFee: number,
            lockerFee: number
        ) {
            // Records new supply of teleBTC
            let newTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Records new teleBTC and TDT balances of user
            let newUserBalanceTeleBTC = await teleBTC.balanceOf(
                recipientAddress
            );
            let newUserBalanceTT = await exchangeToken.balanceOf(
                recipientAddress
            );

            // Records new teleBTC and TDT balances of teleporter
            let newDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            let newDeployerBalanceTT = await exchangeToken.balanceOf(deployerAddress);

            // Checks enough teleBTC has been minted for user
            await expect(newUserBalanceTeleBTC).to.equal(
                oldUserBalanceTeleBTC.add(
                    bitcoinAmount - lockerFee - teleporterFee - protocolFee
                )
            );

            // Checks that enough teleBTC has been minted for teleporter
            await expect(newDeployerBalanceTeleBTC).to.equal(
                oldDeployerBalanceTeleBTC.add(teleporterFee)
            );

            // Checks that user TT balance hasn't changed
            await expect(newUserBalanceTT).to.equal(
                oldUserBalanceTT
            );

            // Checks that correct amount of teleBTC has been minted for protocol
            await expect(
                await teleBTC.balanceOf(TREASURY)
            ).to.equal(protocolFee);

            // Checks that correct amount of teleBTC has been minted for locker
            await expect(
                await teleBTC.balanceOf(lockerAddress)
            ).to.equal(lockerFee);

            // Checks extra teleBTC hasn't been minted
            await expect(newTotalSupplyTeleBTC).to.equal(
                oldTotalSupplyTeleBTC.add(bitcoinAmount)
            );
        }

        beforeEach(async () => {
            // Takes snapshot before adding liquidity
            snapshotId = await takeSnapshot(deployer.provider);

            // Adds liquidity to teleBTC-TDT liquidity pool
            await teleBTC.addMinter(deployerAddress)
            await teleBTC.mint(deployerAddress, 10000000);
            await teleBTC.approve(uniswapV2Router02.address, 10000);
            await exchangeToken.approve(uniswapV2Router02.address, 10000);
            let addedLiquidityA = 10000;
            let addedLiquidityB = 10000;
            
            // console.log(uniswapV2Router02)
            // await uniswapV2Factory.createPair(teleBTC.address, exchangeToken.address);

            await uniswapV2Router02.addLiquidity(
                teleBTC.address,
                exchangeToken.address,
                addedLiquidityA,
                addedLiquidityB,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                1000000000000000, // Long deadline
            );

            // Creates liquidity pool of TeleBTC-WETH and adds liquidity in it
            await teleBTC.approve(uniswapV2Router02.address, 10000);
            await uniswapV2Router02.addLiquidityETH(
                teleBTC.address,
                10000,
                0, // Minimum added liquidity for first token
                0, // Minimum added liquidity for second token
                deployerAddress,
                10000000000000, // Long deadline
                {value: 10000}
            );


            let liquidityPoolAddress = await uniswapV2Factory.getPair(
                teleBTC.address,
                exchangeToken.address
            );

            // Records total supply of teleBTC
            oldTotalSupplyTeleBTC = await teleBTC.totalSupply();

            // Loads teleBTC-TDT liquidity pool
            uniswapV2Pair = await uniswapV2Pair__factory.attach(liquidityPoolAddress);
            // Records current reserves of teleBTC and TT
            if (await uniswapV2Pair.token0() == teleBTC.address) {
                [oldReserveTeleBTC, oldReserveTT] = await uniswapV2Pair.getReserves();
            } else {
                [oldReserveTT, oldReserveTeleBTC] = await uniswapV2Pair.getReserves()
            }

            // Records current teleBTC and TT balances of user and teleporter
            oldUserBalanceTeleBTC = await teleBTC.balanceOf(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress
            );
            oldDeployerBalanceTeleBTC = await teleBTC.balanceOf(deployerAddress);
            oldUserBalanceTT = await exchangeToken.balanceOf(
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.recipientAddress
            );
            oldDeployerBalanceTT = await exchangeToken.balanceOf(deployerAddress);

            
            await ccExchangeRouter.setInstantRouter(deployerAddress)
            await addLockerToLockers();

            await ccExchangeRouter.setThirdPartyAddress(1, THIRD_PARTY_ADDRESS)
            await ccExchangeRouter.setThirdPartyFee(1, THIRD_PARTY_PERCENTAGE_FEE)
        });

        afterEach(async () => {
            await revertProvider(signer1.provider, snapshotId);
        });

        it("Third party gets its fee", async function () {
            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee, thirdPartyFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.bitcoinAmount - teleporterFee - lockerFee - protocolFee - thirdPartyFee,
                oldReserveTeleBTC,
                oldReserveTT
            );
            
            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))
            await expect(
                ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            )
            .to.emit(ccExchangeRouter, 'NewWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.bitcoinAmount - teleporterFee - lockerFee - protocolFee - thirdPartyFee,
                    expectedOutputAmount
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.appId,
                1,
                [teleporterFee, lockerFee, protocolFee, thirdPartyFee, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            );

            await expect(
                await teleBTC.balanceOf(THIRD_PARTY_ADDRESS)
            ).to.equal(thirdPartyFee)
        })

        it("can change third party address", async function () {
            let NEW_THIRD_PARTY_ADDRESS = "0x0000000000000000000000000000000000000201"
            await ccExchangeRouter.setThirdPartyAddress(1, NEW_THIRD_PARTY_ADDRESS)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee, thirdPartyFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.bitcoinAmount - teleporterFee - lockerFee - protocolFee - thirdPartyFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await expect(
                await teleBTC.balanceOf(NEW_THIRD_PARTY_ADDRESS)
            ).to.equal(0)

            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))
            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            )
            .to.emit(ccExchangeRouter, 'NewWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.bitcoinAmount - teleporterFee - lockerFee - protocolFee - thirdPartyFee,
                    expectedOutputAmount
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.appId,
                1,
                [teleporterFee, lockerFee, protocolFee, thirdPartyFee, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            );

            await expect(
                await teleBTC.balanceOf(NEW_THIRD_PARTY_ADDRESS)
            ).to.equal(thirdPartyFee)
        })

        it("can change third party fee", async function () {
            THIRD_PARTY_PERCENTAGE_FEE = 50
            await ccExchangeRouter.setThirdPartyFee(1, THIRD_PARTY_PERCENTAGE_FEE)

            // Replaces dummy address in vout with exchange token address
            let vout = CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.vout;
            vout = vout.replace(DUMMY_ADDRESS, exchangeToken.address.slice(2, exchangeToken.address.length));
            // console.log("1", CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty, oldReserveTeleBTC, oldReserveTT)
            // Calculates fees
            let [lockerFee, teleporterFee, protocolFee, thirdPartyFee] = calculateFees(
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty
            );

            // Finds expected output amount that user receives (input token is fixed)
            
            let expectedOutputAmount = await uniswapV2Router02.getAmountOut(
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.bitcoinAmount - teleporterFee - lockerFee - protocolFee - thirdPartyFee,
                oldReserveTeleBTC,
                oldReserveTT
            );

            await expect(
                await teleBTC.balanceOf(THIRD_PARTY_ADDRESS)
            ).to.equal(0)

            // Exchanges teleBTC for TT
            // console.log(await ccExchangeRouter.isRequestUsed("0x47b4ca636567ba248e2b1f46fc0ef7023269ddb8b7cb0cf984df0fee5d3d6d5f"))
            await expect(
                await ccExchangeRouter.wrapAndSwap(
                    {
                        version: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.version,
                        vin: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.vin,
                        vout,
                        locktime: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.locktime,
                        blockNumber: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.blockNumber,
                        intermediateNodes: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.intermediateNodes,
                        index: CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.index,
                    },
                    LOCKER1_LOCKING_SCRIPT,
                    [teleBTC.address, exchangeToken.address]
                )
            )
            .to.emit(ccExchangeRouter, 'NewWrapAndSwap').withArgs(
                LOCKER_TARGET_ADDRESS,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.recipientAddress,
                [teleBTC.address, exchangeToken.address],
                [
                    CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.bitcoinAmount - teleporterFee - lockerFee - protocolFee - thirdPartyFee,
                    expectedOutputAmount
                ],
                0,
                deployerAddress,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.txId,
                CC_EXCHANGE_REQUESTS.normalCCExchange_WithThirdParty.appId,
                1,
                [teleporterFee, lockerFee, protocolFee, thirdPartyFee, 0],
                CC_EXCHANGE_REQUESTS.normalCCExchange_fixedInput.chainId
            );

            await expect(
                await teleBTC.balanceOf(THIRD_PARTY_ADDRESS)
            ).to.equal(thirdPartyFee)
        })

        it("only owner can set third party address", async function () {
            await expect(
                ccExchangeRouter.connect(signer1).setThirdPartyAddress(1, THIRD_PARTY_ADDRESS)
            ).to.be.revertedWith("Ownable: caller is not the owner")
        })

        it("only owner can set third party fee", async function () {
            await expect(
                ccExchangeRouter.connect(signer1).setThirdPartyFee(1, THIRD_PARTY_PERCENTAGE_FEE)
            ).to.be.revertedWith("Ownable: caller is not the owner")
        })

    });
});