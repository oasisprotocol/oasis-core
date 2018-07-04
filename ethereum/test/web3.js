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
            from: "1cca28600d7491365520b31b466f88647b9839ec",
            gas: 100000,
            gasPrice: 0
        }, resolve);
    });
};

// Only run if directly executed.
if (require.main === module) {
    let HDWalletProvider = require("truffle-hdwallet-provider");
    let web3 = require('web3');
    let mnemonic = 'patient oppose cotton portion chair gentle jelly dice supply salmon blast priority';

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
