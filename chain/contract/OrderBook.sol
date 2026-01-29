// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title OrderBook with hidden-quantity (string) and matching by price, gasFee, block priority
contract OrderBook {
    enum Side { Bid, Ask }

    struct Order {
        uint256 id;
        address maker;
        Side side;
        uint256 price;       // public price used for ordering
        string quantity;     // hidden quantity stored as string
        uint256 gasFee;      // ordering tie-breaker
        uint256 blockNumber; // lower blockNumber gets priority
        bool active;         // active (not cancelled/filled)
    }

    uint256 public nextOrderId = 1;
    mapping(uint256 => Order) public orders;
    uint256[] public bidIds;
    uint256[] public askIds;

    event OrderPlaced(uint256 indexed id, address indexed maker, Side side, uint256 price, uint256 gasFee);
    event OrderCancelled(uint256 indexed id);
    event Trade(uint256 indexed bidId, uint256 indexed askId, uint256 price, string quantityMask);

    /// @notice Place an order. Quantity is stored as a string to hide the numeric amount.
    function placeOrder(Side side, uint256 price, string calldata quantity, uint256 gasFee) external returns (uint256) {
        uint256 id = nextOrderId++;
        orders[id] = Order({
            id: id,
            maker: msg.sender,
            side: side,
            price: price,
            quantity: quantity,
            gasFee: gasFee,
            blockNumber: block.number,
            active: true
        });

        if (side == Side.Bid) {
            bidIds.push(id);
        } else {
            askIds.push(id);
        }

        emit OrderPlaced(id, msg.sender, side, price, gasFee);
        return id;
    }

    /// @notice Cancel an active order (only maker can cancel)
    function cancelOrder(uint256 id) external {
        Order storage o = orders[id];
        require(o.maker == msg.sender, "not maker");
        require(o.active, "not active");
        o.active = false;
        emit OrderCancelled(id);
    }

    /// @dev find best bid id (returns 0 if none)
    function _findBestBid() internal view returns (uint256 bestId) {
        uint256 bestPrice = 0;
        uint256 bestGas = 0;
        uint256 bestBlock = type(uint256).max;
        bestId = 0;
        for (uint256 i = 0; i < bidIds.length; i++) {
            uint256 id = bidIds[i];
            Order storage o = orders[id];
            if (!o.active) continue;
            // higher price preferred
            if (o.price > bestPrice
                || (o.price == bestPrice && o.gasFee > bestGas)
                || (o.price == bestPrice && o.gasFee == bestGas && o.blockNumber < bestBlock)) {
                bestPrice = o.price;
                bestGas = o.gasFee;
                bestBlock = o.blockNumber;
                bestId = id;
            }
        }
    }

    /// @dev find best ask id (returns 0 if none)
    function _findBestAsk() internal view returns (uint256 bestId) {
        uint256 bestPrice = type(uint256).max;
        uint256 bestGas = 0;
        uint256 bestBlock = type(uint256).max;
        bestId = 0;
        for (uint256 i = 0; i < askIds.length; i++) {
            uint256 id = askIds[i];
            Order storage o = orders[id];
            if (!o.active) continue;
            // lower price preferred for asks
            if (o.price < bestPrice
                || (o.price == bestPrice && o.gasFee > bestGas)
                || (o.price == bestPrice && o.gasFee == bestGas && o.blockNumber < bestBlock)) {
                bestPrice = o.price;
                bestGas = o.gasFee;
                bestBlock = o.blockNumber;
                bestId = id;
            }
        }
    }

    /// @notice Run matching engine. Matches best bid/ask pairs where bid.price >= ask.price.
    /// @dev This naive on-chain matcher pairs whole orders (quantity is opaque string). It marks both orders inactive and emits a Trade event.
    function matchOrders(uint256 maxMatches) external returns (uint256 matches) {
        matches = 0;
        while (matches < maxMatches) {
            uint256 bidId = _findBestBid();
            uint256 askId = _findBestAsk();
            if (bidId == 0 || askId == 0) break;
            Order storage bid = orders[bidId];
            Order storage ask = orders[askId];
            if (bid.price < ask.price) break; // no cross

            // mark as matched/inactive
            bid.active = false;
            ask.active = false;

            // choose trade price (here we take ask.price)
            uint256 tradePrice = ask.price;

            // quantity is hidden. We emit a masked quantity string to signal trade happened.
            string memory mask = "HIDDEN";
            emit Trade(bidId, askId, tradePrice, mask);

            matches += 1;
        }
    }

    /// @notice Helpers to read orders length
    function getBidCount() external view returns (uint256) { return bidIds.length; }
    function getAskCount() external view returns (uint256) { return askIds.length; }
}
