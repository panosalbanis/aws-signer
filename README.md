# aws-signer
A very minimal es6 library to sign AWS axios requests

## Build Status
[![Build Status](https://travis-ci.com/panosalbanis/aws-signer.svg?branch=master)](https://travis-ci.com/panosalbanis/aws-signer)

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
  url: 'https://s3.eu-west-1.amazonaws.com/',
  method: 'post',
  headers: {
     Accept: '*/*'
  },
  data: {}
};

sign(opts, config);

axios(opts).then(console.log);
```
