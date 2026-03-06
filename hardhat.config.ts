import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

import hardhatTypechain from "@nomicfoundation/hardhat-typechain";

import type { HardhatUserConfig } from "hardhat/config";

import hardhatContractSizer from "@solidstate/hardhat-contract-sizer";

const config: HardhatUserConfig = {
  plugins: [hardhatToolboxMochaEthers, hardhatTypechain, hardhatContractSizer],
  solidity: {
    compilers: [
      {
        version: "0.8.34",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          evmVersion: "paris",
        },
      },
    ],
  },
  typechain: {
    outDir: "generated-types/ethers",
    discriminateTypes: true,
  },
  contractSizer: {
    alphaSort: false,
    runOnCompile: true,
    strict: false,
    flat: true,
  },
};

export default config;
