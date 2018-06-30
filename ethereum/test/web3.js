/**
 * This script runs as a directly executed binary to drive transactions on a
 * Selected ethereum network. It operates the truffle HDWallet provider to
 * send 0-value transactions to itself at a fixed interval.
 */

var HDWalletProvider = require("truffle-hdwallet-provider");
var web3 = require('web3');
var mnemonic = "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";

var makeTxn = function () {
    client.eth.sendTransaction({
        from: "627306090abab3a6e1400e9345bc60c78a8bef57",
        gas: 100000,
        gasPrice: 0
    });
};

// If directly executed.
if (require.main === module) {
    if (process.argv.length < 4) {
        console.warn("Usage: web3.js <provider> <interval-ms>");
        exit(0);
    }
    var provider = new HDWalletProvider(mnemonic, process.argv[2]);
    var client = new web3();
    client.setProvider(provider);
    setInterval(makeTxn.bind(client), process.argv[3]);
}