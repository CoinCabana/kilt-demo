


require('dotenv').config();

const {cryptoWaitReady} = require("@polkadot/util-crypto");
const Kilt = require("@kiltprotocol/sdk-js");
// const attester = require('./attester');
// const getAccount = require("./attester/getAccount");
// const {transformBalances} = require("./transformBalances");

const secret = 'receive clutch item involve chaos clutch furnace arrest claw isolate okay together';

// load the node address from .env
const {
    WSS_ADDRESS: nodeUrl,
    CLAIMER_MNEMONIC: claimerSecret,
    ATTESTER_MNEMONIC: attesterSecret,
    ATTESTER_DID_URI: attesterDidUri
} = process.env

// Fetch the keyring pair for the Kilt-Node seed address
const seedKeyring = new Kilt.Utils.Keyring({
    ss58Format: 38,
    type: 'ed25519',
})

async function main() {
    await cryptoWaitReady()
    await Kilt.init({address: nodeUrl})

    // const seedAccount = getAccount(secret);
    const seedAccount = seedKeyring.addFromMnemonic(secret);
    const seedAddress = seedAccount.address;

    const keyring = new Kilt.Utils.Keyring({ ss58Format: 38, type: 'sr25519'});
    const attesterAccount = keyring.addFromMnemonic(attesterSecret);

    // const attesterAccount = accountFactory.createAccount(attesterSecret);

    // Creates a light DID for the claimer
    // const { claimerLightDid, keystore: claimerKeystore } =
    //     await createClaimerLightDid(await keystoreGeneration(), claimerMnemonic)

    const balances = await Kilt.Balance.getBalances(attesterAccount.address);

    console.log('BALANCES - ', attesterAccount.address);
    console.log(JSON.stringify(balances,null,2));

    // Checks if the attester has balance, if no balance has been found the script will end
    if (balances.free === 0) {
        throw new Error(
            `The following address: ${seedAddress} holds no tokens, please request tokens from the faucet`
        )
    }

    // await createAttesterOnChain();

    // await checkFullDID(attesterDidUri);

    // Claimer gets ctype from Attester
    // const ctypeJSON = await attester.getCtype();
    //
    // console.log(ctypeJSON);

    // await transfer(seedAccount, attesterAccount.address, 500);
    //
    // console.log(attesterAccount.address);

    // we can disconnect
    await Kilt.disconnect();
}

async function checkFullDID (did) {
    const attesterFullDid = (await Kilt.Did.resolveDoc(did))?.details;// as IDidDetails

    console.log('Full DID', attesterFullDid)
}

async function transfer(fromAccount, address, transferAmount) {
    await Kilt.Balance.makeTransfer(address, transferAmount, 0).then((tx) =>
        Kilt.BlockchainUtils.signAndSubmitTx(tx, fromAccount, {
            resolveOn: Kilt.BlockchainUtils.IS_FINALIZED,
            reSign: true,
        })
    );

    const balances2 = await Kilt.Balance.getBalances(address);

    console.log('BALANCES2');
    console.log(JSON.stringify(balances2,null,2));
}

main();