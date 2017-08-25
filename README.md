# aws-signer
A very minimal es6 library to sign AWS requests

## Installation
```
npm install --save aws-signer
```

## Usage
```
import { sign } from 'aws-signer';

const config = {
  region: region,
  service: service,
  accessKeyId: accessKeyId,
  secretAccessKey: secretAccessKey
};

const opts = {
  url: 'htts://s3.eu-west-1.amazonaws.com/',
  method: 'post',
  headers: {
     Accept: '*/*'
  },
  data: {}
};

sign(opts, config);

axios(opts).then(console.log);
```
