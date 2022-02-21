require('dotenv').config();

class AppEnv {
    WSS_ADDRESS: string;
    CLAIMER_DID_URI: string;
    // CLAIMER_MNEMONIC="quick catch expect matter sound clump employ topic inquiry error practice fitness"
    // CLAIMER_ADDRESS=4qwnPvFjEaMt9Z9VbSLVnxLEkEWyQreMHvHtUZi3o7Txt3x9
    ATTESTER_DID_URI: string;
    // ATTESTER_MNEMONIC="fork powder vendor depart license question snap bid seed witness library juice"
    // ATTESTER_ADDRESS=4sNHVAzCENauiShif4nQm5E5Bwhbnv9Ch9655z1xjcf3WYda
}

export const appEnv:AppEnv = Object.assign(new AppEnv(), process.env);

