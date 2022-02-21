

### Install dependencies
yarn install

### Build
npm run build

### create ENV file
vi .env
[enter env variables and save]


### Run docker for local kilt-node
docker run -d --name kilt-node -p 9944:9944 kiltprotocol/mashnet-node:develop --dev --ws-port 9944 --ws-external --rpc-external --tmp

### Run demo
node dist/demo.js

