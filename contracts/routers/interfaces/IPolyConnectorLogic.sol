// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.8.4;

import "@teleportdao/btc-evm-bridge/contracts/types/ScriptTypesEnum.sol";
import "@teleportdao/teleordinal/contracts/TeleOrdinalLib.sol";

interface IPolyConnectorLogic {

    // Events
    
   	event NewBurn(
        address exchangeConnector,
		address inputToken,
		uint inputAmount,
		address indexed userTargetAddress,
		bytes userScript,
		ScriptTypes scriptType,
		address lockerTargetAddress,
		uint requestIdOfLocker,
        address[] path
	);

   	event FailedBurn(
		address exchangeConnector,
		address inputToken,
		uint inputAmount,
		address indexed userTargetAddress,
		bytes userScript,
		ScriptTypes scriptType,
        address[] path
	);

    event MsgReceived(
        uint uniqueCounter,
        string functionName,
        bytes data
    );

    event AcrossUpdated( 
        address oldAcross,
        address newAcross
    );

    event EthConnectorUpdated( 
        address oldEthConnector,
        address newEthConnector
    );

    event BurnRouterUpdated( 
        address oldBurnRouter,
        address newBurnRouter
    );

    event LockersProxyUpdated( 
        address oldLockersProxy,
        address newLockersProxy
    );

    function setAcross(address _across) external;

    function setAcrossV3(address _acrossV3) external;

    function setEthConnectorProxy(address _ethConnectorProxy) external;

    function setBurnRouterProxy(address _burnRouterProxy) external;

    function setLockersProxy(address _lockersProxy) external;

    function withdrawFundsToEth(
        bytes memory _message,
        // address _token,
        // uint _amount,
        // int64 _relayerFeePercentage,
        uint8 _v, 
        bytes32 _r, 
        bytes32 _s
    ) external;

    function retrySwapAndUnwrap(
        bytes memory _message,
        uint8 _v, 
        bytes32 _r, 
        bytes32 _s
    ) external;

    function emergencyWithdraw(
        address _token,
        address _to,
        uint _amount
    ) external;
}