const awsSigner = require('./index.js')

describe('aws-signer', () => {

    // Test examples are taken form form AWS
    // https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html

    let date
    const fakeDate = new Date('2015-08-30T12:36:00.000Z')
    const config = {
        region: 'us-east-1',
        service: 'service',
        accessKeyId: 'AKIDEXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
    };

    beforeEach(() => {
        date = global.Date
        global.Date = function () {
            return fakeDate
        }
    })

    afterEach(() => {
        global.Date = date
    })

    it('exports a function named `sign`', () => {
        expect(typeof awsSigner.sign).toBe('function')
    })

    it('Adds a valid signature to an empty post request', () => {
        const opts = {
            url: 'http://example.amazonaws.com/',
            method: 'post'
        };

        awsSigner.sign(opts, config)

        expect(typeof opts.headers.Authorization).toBe('string')
        expect(opts.headers.Authorization).toEqual('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b')
    })

    it('Adds a valid signature to an empty get request', () => {
        const opts = {
            url: 'http://example.amazonaws.com/',
            method: 'get'
        };

        awsSigner.sign(opts, config)

        expect(typeof opts.headers.Authorization).toBe('string')
        expect(opts.headers.Authorization).toEqual('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31')
    })

    it('Adds a valid signature to a get request with query params', () => {
        const opts = {
            url: 'http://example.amazonaws.com/?Param1=value1&Param1=value2',
            method: 'get'
        };

        awsSigner.sign(opts, config)

        expect(typeof opts.headers.Authorization).toBe('string')
        expect(opts.headers.Authorization).toEqual('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5772eed61e12b33fae39ee5e7012498b51d56abc0abb7c60486157bd471c4694')
    })

    it('Adds a valid signature to a get request with a path', () => {
        const opts = {
            url: 'http://example.amazonaws.com/ሴ',
            method: 'get'
        };

        awsSigner.sign(opts, config)

        expect(typeof opts.headers.Authorization).toBe('string')
        expect(opts.headers.Authorization).toEqual('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85')
    })
})
