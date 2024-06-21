// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Counter } from "../src/Counter.sol";

contract ResolverTest is Test {
  uint256 a;

  function setUp() public {
    a = 5;
  }

  function test() public {
    console2.log("a", a);
  }
}
