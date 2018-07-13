// Convert a bip39 mnemonic into a raw private key that can be used by geth
// per http://ethereum.stackexchange.com/questions/33395

var hdkey = require("ethereumjs-wallet/hdkey");
var bip39 = require("bip39");

if (process.argv.length < 3) {
  console.warn("Usage: keyconversion.js 'mnemonic...'");
  process.exit(-1);
}
var mnemonic = process.argv[2];
var path = "m/44'/60'/0'/0/0";

var hdwallet = hdkey.fromMasterSeed(bip39.mnemonicToSeed(mnemonic));
var wallet = hdwallet.derivePath(path).getWallet();
console.log(wallet.getPrivateKeyString());
