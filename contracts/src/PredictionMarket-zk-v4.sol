// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pool} from "v4-core/libraries/Pool.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {LiquidityAmounts} from "v4-periphery/src/libraries/LiquidityAmounts.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary} from "v4-core/types/BalanceDelta.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {BeforeSwapDelta} from "v4-core/types/BeforeSwapDelta.sol";
import {IUnlockCallback} from "v4-core/interfaces/callback/IUnlockCallback.sol";
import {PoolIdLibrary} from "v4-core/types/PoolId.sol";

// Import the SP1 verifier interface
import {ISP1Verifier} from "sp1-contracts/src/ISP1Verifier.sol";

contract PredictionMarketHook is BaseHook, Ownable, IUnlockCallback {
    using CurrencyLibrary for Currency;
    using SafeERC20 for IERC20;
    using PoolIdLibrary for PoolKey;

    // ----------------------------
    // Declare poolManager explicitly to resolve undeclared identifier errors.
    // ----------------------------
    // IPoolManager public poolManager;

    // ----------------------------
    // Market state variables
    // ----------------------------
    bool public marketOpen;
    bool public marketClosed;
    bool public resolved;
    bool public outcomeIsYes;
    uint256 public startTime;
    uint256 public endTime;

    // ----------------------------
    // Operation context for callbacks
    // ----------------------------
    enum OperationType {
        None,
        AddLiquidityYes,
        AddLiquidityNo,
        RemoveLiquidityYes,
        RemoveLiquidityNo,
        Swap
    }

    struct OperationContext {
        OperationType operationType;
        PoolKey poolKey;
        IPoolManager.ModifyLiquidityParams modifyParams;
        IPoolManager.SwapParams swapParams;
        address recipient;
    }

    OperationContext public currentOperation;

    // ----------------------------
    // Token and pool variables
    // ----------------------------
    address public immutable usdc;
    address public immutable yesToken;
    address public immutable noToken;

    uint256 public usdcInYesPool = 0;
    uint256 public usdcInNoPool = 0;
    uint256 public yesTokensInPool = 0;
    uint256 public noTokensInPool = 0;

    PoolKey public yesPoolKey;
    PoolKey public noPoolKey;

    uint256 public totalUSDCCollected;
    uint256 public hookYesBalance;
    uint256 public hookNoBalance;
    
    mapping(address => bool) public hasClaimed;

    // Used to determine token ordering in pools
    bool public isUSDCToken0InYesPool;
    bool public isUSDCToken0InNoPool;

    // ----------------------------
    // SP1 zk-proof variables for market resolution
    // ----------------------------
    address public sp1Verifier;
    bytes32 public marketResolutionVKey;

    // ----------------------------
    // Events
    // ----------------------------
    event MarketOpened();
    event MarketClosed();
    event OutcomeResolved(bool outcomeIsYes);
    event Claimed(address indexed user, uint256 amount);
    event PoolsInitialized(address yesPool, address noPool);
    event LiquidityAdded(address pool, uint256 amount0, uint256 amount1);
    event SwapExecuted(address user, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);
    event MarketReset();

    // ----------------------------
    // Constructor
    // ----------------------------
    constructor(
        IPoolManager _poolManager,
        address _usdc,
        address _yesToken,
        address _noToken,
        address _sp1Verifier,
        bytes32 _marketResolutionVKey
    ) BaseHook(_poolManager) Ownable(tx.origin) {
        poolManager = _poolManager; // Assign the pool manager

        usdc = _usdc;
        yesToken = _yesToken;
        noToken = _noToken;
        
        sp1Verifier = _sp1Verifier;
        marketResolutionVKey = _marketResolutionVKey;
        
        marketOpen = false;
        marketClosed = false;
        resolved = false;
    }

    // ----------------------------
    // Market management functions
    // ----------------------------
    function openMarket() external onlyOwner {
        require(!marketOpen, "Market already open");
        require(!marketClosed, "Market already closed");
        require(!resolved, "Market already resolved");
        
        marketOpen = true;
        startTime = block.timestamp;
        endTime = block.timestamp + 7 days;
        emit MarketOpened();
    }
    
    function closeMarket() external onlyOwner {
        require(marketOpen, "Market not open");
        require(!marketClosed, "Market already closed");
        
        marketClosed = true;
        endTime = block.timestamp;
        emit MarketClosed();
    }
    
    function resetMarket() external onlyOwner {
        require(resolved, "Current market not resolved yet");
        
        marketOpen = false;
        marketClosed = false;
        resolved = false;
        outcomeIsYes = false;
        
        usdcInYesPool = 0;
        usdcInNoPool = 0;
        yesTokensInPool = 0;
        noTokensInPool = 0;
        
        totalUSDCCollected = 0;
        hookYesBalance = 0;
        hookNoBalance = 0;
        
        yesPoolKey = PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(address(0)),
            fee: 0,
            tickSpacing: 0,
            hooks: IHooks(address(0))
        });
        
        noPoolKey = PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(address(0)),
            fee: 0,
            tickSpacing: 0,
            hooks: IHooks(address(0))
        });
        
        emit MarketReset();
    }

    // ----------------------------
    // Hook Permissions & Pre-/Post- Operations
    // ----------------------------
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: true,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function _beforeAddLiquidity(
        address, 
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) internal view override returns (bytes4) {
        require(!marketClosed, "Market closed");
        require(_isValidPool(key), "Invalid pool");
        return IHooks.beforeAddLiquidity.selector;
    }

    function _beforeRemoveLiquidity(
        address, 
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) internal view override returns (bytes4) {
        require(_isValidPool(key), "Invalid pool");
        require(marketOpen && !marketClosed, "Market not active");
        return IHooks.beforeRemoveLiquidity.selector;
    }

    function _beforeSwap(
        address, 
        PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        bytes calldata
    ) internal view override returns (bytes4, BeforeSwapDelta, uint24) {
        require(_isValidPool(key), "Invalid pool");
        require(marketOpen && !marketClosed, "Market not active");
        return (IHooks.beforeSwap.selector, BeforeSwapDelta.wrap(0), 0);
    }
    
    function _afterSwap(
        address, 
        PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        BalanceDelta delta,
        bytes calldata
    ) internal override returns (bytes4, int128) {
        bool isYesPool = _isYesPool(key);
        
        int256 usdcDelta;
        int256 tokenDelta;
        
        if (isYesPool) {
            usdcDelta = isUSDCToken0InYesPool ? delta.amount0() : delta.amount1();
            tokenDelta = isUSDCToken0InYesPool ? delta.amount1() : delta.amount0();
            
            if (usdcDelta < 0) {
                usdcInYesPool += uint256(-usdcDelta);
            } else {
                require(usdcInYesPool >= uint256(usdcDelta), "Insufficient USDC in YES pool");
                usdcInYesPool -= uint256(usdcDelta);
            }
            
            if (tokenDelta < 0) {
                yesTokensInPool += uint256(-tokenDelta);
            } else {
                require(yesTokensInPool >= uint256(tokenDelta), "Insufficient YES tokens in pool");
                yesTokensInPool -= uint256(tokenDelta);
            }
            
            if (usdcDelta < 0 || tokenDelta < 0) {
                emit LiquidityAdded(
                    yesToken, 
                    usdcDelta < 0 ? uint256(-usdcDelta) : 0, 
                    tokenDelta < 0 ? uint256(-tokenDelta) : 0
                );
            }
        } else {
            usdcDelta = isUSDCToken0InNoPool ? delta.amount0() : delta.amount1();
            tokenDelta = isUSDCToken0InNoPool ? delta.amount1() : delta.amount0();
            
            if (usdcDelta < 0) {
                usdcInNoPool += uint256(-usdcDelta);
            } else {
                require(usdcInNoPool >= uint256(usdcDelta), "Insufficient USDC in NO pool");
                usdcInNoPool -= uint256(usdcDelta);
            }
            
            if (tokenDelta < 0) {
                noTokensInPool += uint256(-tokenDelta);
            } else {
                require(noTokensInPool >= uint256(tokenDelta), "Insufficient NO tokens in pool");
                noTokensInPool -= uint256(tokenDelta);
            }
            
            if (usdcDelta < 0 || tokenDelta < 0) {
                emit LiquidityAdded(
                    noToken, 
                    usdcDelta < 0 ? uint256(-usdcDelta) : 0, 
                    tokenDelta < 0 ? uint256(-tokenDelta) : 0
                );
            }
        }
        
        return (IHooks.afterSwap.selector, 0);
    }

    function checkOwner() public view returns (address) {
        return owner();
    }
    
    // ----------------------------
    // Pool Initialization & Liquidity Management
    // ----------------------------
    function initializePools() external onlyOwner {
        require(!marketOpen && !marketClosed && !resolved, "Cannot initialize active market");
        
        // Initialize YES pool
        isUSDCToken0InYesPool = uint160(usdc) < uint160(yesToken);
        yesPoolKey = PoolKey({
            currency0: Currency.wrap(isUSDCToken0InYesPool ? usdc : yesToken),
            currency1: Currency.wrap(isUSDCToken0InYesPool ? yesToken : usdc),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(this))
        });
        IPoolManager(address(poolManager)).initialize(yesPoolKey, TickMath.getSqrtPriceAtTick(0));
        _addLiquidity(yesPoolKey, 50_000e6, 50_000e18);
        usdcInYesPool = 50_000e6;
        yesTokensInPool = 50_000e18;

        // Initialize NO pool
        isUSDCToken0InNoPool = uint160(usdc) < uint160(noToken);
        noPoolKey = PoolKey({
            currency0: Currency.wrap(isUSDCToken0InNoPool ? usdc : noToken),
            currency1: Currency.wrap(isUSDCToken0InNoPool ? noToken : usdc),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(this))
        });
        IPoolManager(address(poolManager)).initialize(noPoolKey, TickMath.getSqrtPriceAtTick(0));
        _addLiquidity(noPoolKey, 50_000e6, 50_000e18);
        usdcInNoPool = 50_000e6;
        noTokensInPool = 50_000e18;
        
        emit PoolsInitialized(yesToken, noToken);
    }

    function _addLiquidity(PoolKey memory key, uint256 usdcAmount, uint256 tokenAmount) internal {
        bool isYes = _isYesPool(key);
        bool isUSDCToken0 = isYes ? isUSDCToken0InYesPool : isUSDCToken0InNoPool;
        address token = isYes ? yesToken : noToken;
        
        uint256 amount0 = isUSDCToken0 ? usdcAmount : tokenAmount;
        uint256 amount1 = isUSDCToken0 ? tokenAmount : usdcAmount;
        
        IERC20(Currency.unwrap(key.currency0)).approve(address(poolManager), 0);
        IERC20(Currency.unwrap(key.currency0)).approve(address(poolManager), amount0);
        
        IERC20(Currency.unwrap(key.currency1)).approve(address(poolManager), 0);
        IERC20(Currency.unwrap(key.currency1)).approve(address(poolManager), amount1);

        uint160 sqrtPriceAX96 = TickMath.getSqrtPriceAtTick(-887272);
        uint160 sqrtPriceBX96 = TickMath.getSqrtPriceAtTick(887272);
        uint160 sqrtPriceX96 = TickMath.getSqrtPriceAtTick(0);

        uint128 liquidity = LiquidityAmounts.getLiquidityForAmounts(
            sqrtPriceX96,
            sqrtPriceAX96,
            sqrtPriceBX96,
            amount0,
            amount1
        );

        IPoolManager.ModifyLiquidityParams memory params = IPoolManager.ModifyLiquidityParams({
            tickLower: -887220,
            tickUpper: 887220,
            liquidityDelta: int128(liquidity),
            salt: keccak256("prediction_market")
        });

        currentOperation = OperationContext({
            operationType: isYes ? OperationType.AddLiquidityYes : OperationType.AddLiquidityNo,
            poolKey: key,
            modifyParams: params,
            swapParams: IPoolManager.SwapParams({
                zeroForOne: false,
                amountSpecified: 0,
                sqrtPriceLimitX96: 0
            }),
            recipient: address(0)
        });

        poolManager.unlock(new bytes(0));
        
        currentOperation = OperationContext({
            operationType: OperationType.None,
            poolKey: PoolKey({
                currency0: Currency.wrap(address(0)),
                currency1: Currency.wrap(address(0)),
                fee: 0,
                tickSpacing: 0,
                hooks: IHooks(address(0))
            }),
            modifyParams: IPoolManager.ModifyLiquidityParams({
                tickLower: 0,
                tickUpper: 0,
                liquidityDelta: 0,
                salt: bytes32(0)
            }),
            swapParams: IPoolManager.SwapParams({
                zeroForOne: false,
                amountSpecified: 0,
                sqrtPriceLimitX96: 0
            }),
            recipient: address(0)
        });
    }

    // ----------------------------
    // Swap Functions
    // ----------------------------
    function swapUSDCForYesTokens(uint256 usdcAmount) external returns (uint256 tokenAmount) {
        return _swapExactInput(usdc, yesToken, usdcAmount, msg.sender);
    }
    
    function swapUSDCForNoTokens(uint256 usdcAmount) external returns (uint256 tokenAmount) {
        return _swapExactInput(usdc, noToken, usdcAmount, msg.sender);
    }
    
    function swapYesTokensForUSDC(uint256 tokenAmount) external returns (uint256 usdcAmount) {
        return _swapExactInput(yesToken, usdc, tokenAmount, msg.sender);
    }
    
    function swapNoTokensForUSDC(uint256 tokenAmount) external returns (uint256 usdcAmount) {
        return _swapExactInput(noToken, usdc, tokenAmount, msg.sender);
    }
    
    function swapYesForNoTokens(uint256 yesAmount) external returns (uint256 noAmount) {
        uint256 usdcReceived = _swapExactInput(yesToken, usdc, yesAmount, address(this));
        noAmount = _swapExactInput(usdc, noToken, usdcReceived, msg.sender);
        return noAmount;
    }
    
    function swapNoForYesTokens(uint256 noAmount) external returns (uint256 yesAmount) {
        uint256 usdcReceived = _swapExactInput(noToken, usdc, noAmount, address(this));
        yesAmount = _swapExactInput(usdc, yesToken, usdcReceived, msg.sender);
        return yesAmount;
    }
    
    function swap(
        address tokenIn, 
        address tokenOut, 
        uint256 amountIn, 
        uint256 amountOutMinimum
    ) external returns (uint256 amountOut) {
        require(marketOpen && !marketClosed, "Market not active");
        require(!resolved, "Market resolved");
        
        require(
            (tokenIn == usdc && (tokenOut == yesToken || tokenOut == noToken)) ||
            ((tokenIn == yesToken || tokenIn == noToken) && tokenOut == usdc) ||
            (tokenIn == yesToken && tokenOut == noToken) ||
            (tokenIn == noToken && tokenOut == yesToken),
            "Invalid token pair"
        );
        
        if ((tokenIn == usdc && (tokenOut == yesToken || tokenOut == noToken)) ||
            ((tokenIn == yesToken || tokenIn == noToken) && tokenOut == usdc)) {
            amountOut = _swapExactInput(tokenIn, tokenOut, amountIn, msg.sender);
        } else {
            uint256 usdcReceived = _swapExactInput(tokenIn, usdc, amountIn, address(this));
            amountOut = _swapExactInput(usdc, tokenOut, usdcReceived, msg.sender);
        }
        
        require(amountOut >= amountOutMinimum, "Slippage: insufficient output amount");
        return amountOut;
    }
    
    function _swapExactInput(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        address recipient
    ) internal returns (uint256 amountOut) {
        require(marketOpen && !marketClosed, "Market not active");
        require(!resolved, "Market resolved");
        
        PoolKey memory poolKey;
        bool zeroForOne;
        
        if ((tokenIn == usdc && tokenOut == yesToken) || (tokenIn == yesToken && tokenOut == usdc)) {
            poolKey = yesPoolKey;
            if (tokenIn == Currency.unwrap(poolKey.currency0)) {
                zeroForOne = true;
            } else {
                zeroForOne = false;
            }
        } else if ((tokenIn == usdc && tokenOut == noToken) || (tokenIn == noToken && tokenOut == usdc)) {
            poolKey = noPoolKey;
            if (tokenIn == Currency.unwrap(poolKey.currency0)) {
                zeroForOne = true;
            } else {
                zeroForOne = false;
            }
        } else {
            revert("Unsupported token pair");
        }
        
        if (tokenIn != address(this)) {
            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        }
        IERC20(tokenIn).approve(address(poolManager), amountIn);
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(amountIn),
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
        });
        
        currentOperation = OperationContext({
            operationType: OperationType.Swap,
            poolKey: poolKey,
            modifyParams: IPoolManager.ModifyLiquidityParams({
                tickLower: 0,
                tickUpper: 0,
                liquidityDelta: 0,
                salt: bytes32(0)
            }),
            swapParams: params,
            recipient: recipient
        });
        
        bytes memory swapResult = poolManager.unlock(new bytes(0));
        amountOut = abi.decode(swapResult, (uint256));
        
        currentOperation = OperationContext({
            operationType: OperationType.None,
            poolKey: PoolKey({
                currency0: Currency.wrap(address(0)),
                currency1: Currency.wrap(address(0)),
                fee: 0,
                tickSpacing: 0,
                hooks: IHooks(address(0))
            }),
            modifyParams: IPoolManager.ModifyLiquidityParams({
                tickLower: 0,
                tickUpper: 0,
                liquidityDelta: 0,
                salt: bytes32(0)
            }),
            swapParams: IPoolManager.SwapParams({
                zeroForOne: false,
                amountSpecified: 0,
                sqrtPriceLimitX96: 0
            }),
            recipient: address(0)
        });
        
        return amountOut;
    }

    // ----------------------------
    // Helper functions for pool validation
    // ----------------------------
    function _isYesPool(PoolKey memory key) internal view returns (bool) {
        return (
            (Currency.unwrap(key.currency0) == usdc && Currency.unwrap(key.currency1) == yesToken) ||
            (Currency.unwrap(key.currency0) == yesToken && Currency.unwrap(key.currency1) == usdc)
        );
    }

    function _isValidPool(PoolKey calldata key) internal view returns (bool) {
        return (
            (Currency.unwrap(key.currency0) == usdc && Currency.unwrap(key.currency1) == yesToken) ||
            (Currency.unwrap(key.currency0) == yesToken && Currency.unwrap(key.currency1) == usdc) ||
            (Currency.unwrap(key.currency0) == usdc && Currency.unwrap(key.currency1) == noToken) ||
            (Currency.unwrap(key.currency0) == noToken && Currency.unwrap(key.currency1) == usdc)
        );
    }

    // ----------------------------
    // Market Resolution using SP1 zk-Proof
    // ----------------------------
    /**
     * @notice Resolves the market outcome using an off-chain generated zk-proof.
     * @param _publicValues ABI-encoded public values from the zk-program containing:
     *        - outcome (bool)
     *        - totalUSDCCollected (uint256)
     *        - usdcInYesPool (uint256)
     *        - usdcInNoPool (uint256)
     *        - yesTokensInPool (uint256)
     *        - noTokensInPool (uint256)
     * @param _proofBytes The zk-proof bytes generated off-chain.
     */
    function resolveOutcome(
        bytes calldata _publicValues, 
        bytes calldata _proofBytes
    ) external onlyOwner {
        require(marketClosed, "Market not closed");
        require(!resolved, "Already resolved");
        
        // Verify the SP1 zk-proof for market resolution.
        ISP1Verifier(sp1Verifier).verifyProof(marketResolutionVKey, _publicValues, _proofBytes);
        
        // Decode public values from the proof.
        (bool outcome, uint256 totalUSDC, uint256 poolYesUSDC, uint256 poolNoUSDC, uint256 yesTokens, uint256 noTokens) =
            abi.decode(_publicValues, (bool, uint256, uint256, uint256, uint256, uint256));
        
        outcomeIsYes = outcome;
        totalUSDCCollected = totalUSDC;
        usdcInYesPool = poolYesUSDC;
        usdcInNoPool = poolNoUSDC;
        yesTokensInPool = yesTokens;
        noTokensInPool = noTokens;
        
        resolved = true;
        emit OutcomeResolved(outcome);
    }
    
    // ----------------------------
    // Callback & Internal Operations
    // ----------------------------
    function unlockCallback(bytes calldata data) external override returns (bytes memory) {
        require(msg.sender == address(poolManager), "Unauthorized callback");
        
        if (currentOperation.operationType == OperationType.None) {
            return "";
        }
        
        uint256 outputAmount = 0;
        
        if (currentOperation.operationType == OperationType.AddLiquidityYes || 
            currentOperation.operationType == OperationType.AddLiquidityNo) {
            return _handleAddLiquidity();
        } else if (currentOperation.operationType == OperationType.RemoveLiquidityYes || 
                   currentOperation.operationType == OperationType.RemoveLiquidityNo) {
            return _handleRemoveLiquidity();
        } else if (currentOperation.operationType == OperationType.Swap) {
            outputAmount = _handleSwap(data);
            return abi.encode(outputAmount);
        }
        
        return "";
    }
    
    function _handleAddLiquidity() internal returns (bytes memory) {
        (BalanceDelta delta, ) = poolManager.modifyLiquidity(
            currentOperation.poolKey,
            currentOperation.modifyParams,
            ""
        );
        
        _processBalanceDelta(delta, currentOperation.poolKey);
        
        uint256 safeAmount0 = delta.amount0() < 0 ? uint256(uint128(-delta.amount0())) : 0;
        uint256 safeAmount1 = delta.amount1() < 0 ? uint256(uint128(-delta.amount1())) : 0;
        
        emit LiquidityAdded(
            _isYesPool(currentOperation.poolKey) ? yesToken : noToken,
            safeAmount0,
            safeAmount1
        );
        
        return "";
    }
    
    function _handleRemoveLiquidity() internal returns (bytes memory) {
        (BalanceDelta delta, ) = poolManager.modifyLiquidity(
            currentOperation.poolKey,
            currentOperation.modifyParams,
            ""
        );
        
        _processBalanceDelta(delta, currentOperation.poolKey);
        
        if (currentOperation.operationType == OperationType.RemoveLiquidityYes) {
            usdcInYesPool = 0;
            yesTokensInPool = 0;
        } else {
            usdcInNoPool = 0;
            noTokensInPool = 0;
        }
        
        return "";
    }
    
    function _handleSwap(bytes calldata data) internal returns (uint256 outputAmount) {
        BalanceDelta delta = poolManager.swap(
            currentOperation.poolKey,
            currentOperation.swapParams,
            data
        );
        
        Currency tokenIn;
        Currency tokenOut;
        uint256 amountIn;
        uint256 amountOut;
        
        if (currentOperation.swapParams.zeroForOne) {
            tokenIn = currentOperation.poolKey.currency0;
            tokenOut = currentOperation.poolKey.currency1;
            amountIn = uint256(uint128(-delta.amount0()));
            amountOut = uint256(uint128(delta.amount1()));
        } else {
            tokenIn = currentOperation.poolKey.currency1;
            tokenOut = currentOperation.poolKey.currency0;
            amountIn = uint256(uint128(-delta.amount1()));
            amountOut = uint256(uint128(delta.amount0()));
        }
        
        IERC20(Currency.unwrap(tokenIn)).transfer(
            address(poolManager),
            amountIn
        );
        
        poolManager.settle();
        
        address recipient = currentOperation.recipient == address(0) ? msg.sender : currentOperation.recipient;
        poolManager.take(tokenOut, recipient, amountOut);
        
        emit SwapExecuted(
            recipient,
            Currency.unwrap(tokenIn),
            Currency.unwrap(tokenOut),
            amountIn,
            amountOut
        );
        
        return amountOut;
    }
    
    function _processBalanceDelta(BalanceDelta delta, PoolKey memory key) internal {
        if (delta.amount0() < 0) {
            int128 absAmount0 = -delta.amount0();
            uint256 transferAmount0 = uint256(uint128(absAmount0));
            Currency currency0 = key.currency0;
            
            poolManager.sync(currency0);
            IERC20(Currency.unwrap(currency0)).safeTransfer(address(poolManager), transferAmount0);
            poolManager.settle();
        }
        
        if (delta.amount1() < 0) {
            int128 absAmount1 = -delta.amount1();
            uint256 transferAmount1 = uint256(uint128(absAmount1));
            Currency currency1 = key.currency1;
            
            poolManager.sync(currency1);
            IERC20(Currency.unwrap(currency1)).safeTransfer(address(poolManager), transferAmount1);
            poolManager.settle();
        }
        
        if (delta.amount0() > 0) {
            Currency currency0 = key.currency0;
            uint256 amount0 = uint256(uint128(delta.amount0()));
            poolManager.take(currency0, address(this), amount0);
        }
        
        if (delta.amount1() > 0) {
            Currency currency1 = key.currency1;
            uint256 amount1 = uint256(uint128(delta.amount1()));
            poolManager.take(currency1, address(this), amount1);
        }
    }

    // ----------------------------
    // Claim & View Functions
    // ----------------------------
    function claim() external {
        require(resolved, "Outcome not resolved");
        require(!hasClaimed[msg.sender], "Already claimed");
        
        address winningToken = outcomeIsYes ? yesToken : noToken;
        uint256 userBalance = IERC20(winningToken).balanceOf(msg.sender);
        require(userBalance > 0, "No winning tokens");
        
        uint256 totalWinningTokens = IERC20(winningToken).totalSupply() - (outcomeIsYes ? hookYesBalance : hookNoBalance);
        require(totalWinningTokens > 0, "No winners");
        
        uint256 usdcShare = (userBalance * totalUSDCCollected) / totalWinningTokens;
        
        hasClaimed[msg.sender] = true;
        IERC20(usdc).transfer(msg.sender, usdcShare);
        emit Claimed(msg.sender, usdcShare);
    }
    
    function getOdds() external view returns (uint256 yesOdds, uint256 noOdds) {
        require(marketOpen, "Market not started");
        require(!resolved, "Market resolved");
        
        uint256 totalPoolUSDC = usdcInYesPool + usdcInNoPool;
        if (totalPoolUSDC == 0) {
            return (50, 50);
        }
        
        noOdds = (usdcInYesPool * 100) / totalPoolUSDC;
        yesOdds = (usdcInNoPool * 100) / totalPoolUSDC;
        return (yesOdds, noOdds);
    }

    function _calculatePrice(uint160 sqrtPriceX96) internal pure returns (uint256) {
        uint256 price = uint256(sqrtPriceX96) * uint256(sqrtPriceX96);
        price = price >> 192;
        return price;
    }

    function getTokenPrices() external view returns (uint256 yesPrice, uint256 noPrice) {
        if (yesTokensInPool > 0) {
            yesPrice = (usdcInYesPool * 1e18) / yesTokensInPool;
        } else {
            yesPrice = 0;
        }
        
        if (noTokensInPool > 0) {
            noPrice = (usdcInNoPool * 1e18) / noTokensInPool;
        } else {
            noPrice = 0;
        }
        
        return (yesPrice, noPrice);
    }
    
    function getYesPoolKeyComponents() public view returns (Currency, Currency, uint24, int24, IHooks) {
        return (
            yesPoolKey.currency0,
            yesPoolKey.currency1,
            yesPoolKey.fee,
            yesPoolKey.tickSpacing,
            yesPoolKey.hooks
        );
    }
    
    function getNoPoolKeyComponents() public view returns (Currency, Currency, uint24, int24, IHooks) {
        return (
            noPoolKey.currency0,
            noPoolKey.currency1,
            noPoolKey.fee,
            noPoolKey.tickSpacing,
            noPoolKey.hooks
        );
    }

    function getMarketState() external view returns (
        bool isOpen,
        bool isClosed,
        bool isResolved,
        bool outcome
    ) {
        return (marketOpen, marketClosed, resolved, outcomeIsYes);
    }
}
