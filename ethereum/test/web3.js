/**
 * This script runs as a directly executed binary to drive transactions on a
 * Selected ethereum network. It operates the truffle HDWallet provider to
 * send 0-value transactions to itself at a fixed interval.
 */

var pause = async function (timeout) {
    return new Promise(function (resolve, _reject) {
        setTimeout(resolve, timeout);
    });
};

var makeTxn = function (client) {
    return new Promise(function (resolve, _reject) {
        client.eth.sendTransaction({
            from: "627306090abab3a6e1400e9345bc60c78a8bef57",
            gas: 100000,
            gasPrice: 0
        }, resolve);
    });
};

// Only run if directly executed.
if (require.main === module) {
    let HDWalletProvider = require("truffle-hdwallet-provider");
    let web3 = require('web3');
    let mnemonic = "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";

    if (process.argv.length < 4) {
        console.warn("Usage: web3.js <provider> <interval-ms>");
        process.exit(0);
    }

    let run = async function () {
        let provider = new HDWalletProvider(mnemonic, process.argv[2]);
        let client = new web3();
        await client.setProvider(provider);
        while (true) {
            await pause(process.argv[3]);
            await makeTxn(client);
        }
    };

    run();
}