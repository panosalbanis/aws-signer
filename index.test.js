const awsSigner = require('./index.js')

describe('aws-signer', () => {

    // Test examples are taken form form AWS
    // https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html

    let date

    beforeEach(() => {
        date = global.Date
    })

    afterEach(() => {
        global.Date = date
    })

    it('exports a function named `sign`', () => {
        expect(typeof awsSigner.sign).toBe('function')
    })

    it('Adds a valid signature to an empty post request', () => {
        const fakeDate = new Date('2015-08-30T12:36:00.000Z')

        global.Date = function () {
            return fakeDate
        }
    
        const config = {
            region: 'us-east-1',
            service: 'service',
            accessKeyId: 'AKIDEXAMPLE',
            secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        };

        const opts = {
            url: 'http://example.amazonaws.com/',
            method: 'post'
        };

        awsSigner.sign(opts, config)

        expect(typeof opts.headers.Authorization).toBe('string')
        expect(opts.headers.Authorization).toEqual('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b')
    })
})
