// SPDX-License-Identifier: MIT  
pragma solidity ^0.8.20;

contract Counter {
    int256 public value;

    function inc(int256 x) external {
        value += x;
    }

    function dec(int256 x) external {
        value -= x;
    }

    function echidna_never_negative() public returns (bool) {
        return value >= 0;
    }
}


