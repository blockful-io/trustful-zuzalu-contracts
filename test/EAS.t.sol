// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";

contract EASTest is Test {
  uint256 a;

  function setUp() public {
    a = 5;
  }

  function test_log() public view {
    console2.log("a", a);
  }
}
