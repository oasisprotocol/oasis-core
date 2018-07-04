var HDWalletProvider = require("truffle-hdwallet-provider");
var mnemonic = "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";

module.exports = {
  // See <http://truffleframework.com/docs/advanced/configuration>
  // to customize your Truffle configuration!
  networks: {
    development: {
      host: "127.0.0.1",
      port: 9545,
      network_id: "*",
      gasPrice: 0
    },
    testnet: {
      provider: function () {
        return new HDWalletProvider(mnemonic, "http://localhost:8545/");
      },
      network_id: "*",
      gas: 4600000,
      gasPrice: 0
    }
  }
};
