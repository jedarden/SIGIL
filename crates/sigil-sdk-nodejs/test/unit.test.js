/**
 * Unit tests for @sigil/sdk
 *
 * These tests verify the SDK API structure without requiring a running daemon.
 * Run with: npm test
 */

describe('@sigil/sdk', () => {
  let SigilClient;
  let nativeBinding;

  beforeAll(() => {
    // Load the native binding
    nativeBinding = require('../index.js');
    SigilClient = nativeBinding.SigilClient;
  });

  describe('SigilClient class', () => {
    test('should export SigilClient class', () => {
      expect(typeof SigilClient).toBe('function');
      expect(SigilClient.name).toBe('SigilClient');
    });

    test('should have constructor', () => {
      expect(typeof SigilClient.prototype.constructor).toBe('function');
    });

    test('should have static factory methods', () => {
      expect(typeof SigilClient.withSocketPath).toBe('function');
      expect(typeof SigilClient.withToken).toBe('function');
    });
  });

  describe('Client instantiation', () => {
    test('should create client with default constructor', () => {
      const client = new SigilClient();
      expect(client).toBeInstanceOf(SigilClient);
    });

    test('should create client with custom socket path', () => {
      const client = SigilClient.withSocketPath('/tmp/test.sock');
      expect(client).toBeInstanceOf(SigilClient);
    });

    test('should create client with token loading', () => {
      const client = SigilClient.withToken();
      expect(client).toBeInstanceOf(SigilClient);
    });
  });

  describe('Async methods', () => {
    let client;

    beforeEach(() => {
      client = new SigilClient();
    });

    test('should have connect method returning Promise', () => {
      expect(typeof client.connect).toBe('function');
      const result = client.connect();
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have get method returning Promise', () => {
      expect(typeof client.get).toBe('function');
      const result = client.get('test/path');
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have resolve method returning Promise', () => {
      expect(typeof client.resolve).toBe('function');
      const result = client.resolve('test {{secret:path}}');
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have exists method returning Promise', () => {
      expect(typeof client.exists).toBe('function');
      const result = client.exists('test/path');
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have list method returning Promise', () => {
      expect(typeof client.list).toBe('function');
      const result = client.list('');
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have requestAccess method returning Promise', () => {
      expect(typeof client.requestAccess).toBe('function');
      const result = client.requestAccess('test/path', 'reason');
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have scrub method returning Promise', () => {
      expect(typeof client.scrub).toBe('function');
      const result = client.scrub('output with secrets');
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have status method returning Promise', () => {
      expect(typeof client.status).toBe('function');
      const result = client.status();
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have exec method returning Promise', () => {
      expect(typeof client.exec).toBe('function');
      const result = client.exec('ls', [], null, false, null, 30);
      expect(result).toBeInstanceOf(Promise);
    });

    test('should have list_operations method returning Promise', () => {
      expect(typeof client.list_operations).toBe('function');
      const result = client.list_operations();
      expect(result).toBeInstanceOf(Promise);
    });
  });

  describe('Type exports', () => {
    test('should export types for TypeScript', () => {
      // These types are for TypeScript - at runtime we just verify
      // the binding exports what we need
      expect(nativeBinding).toBeDefined();
    });
  });

  describe('Error handling', () => {
    let client;

    beforeEach(() => {
      client = new SigilClient();
    });

    test('connect should reject when daemon not running', async () => {
      await expect(client.connect()).rejects.toThrow();
    });

    test('get should reject when secret not found', async () => {
      await expect(client.get('nonexistent/secret')).rejects.toThrow();
    });

    test('exists should handle connection errors', async () => {
      await expect(client.exists('test/path')).rejects.toThrow();
    });
  });

  describe('Method signatures', () => {
    let client;

    beforeEach(() => {
      client = new SigilClient();
    });

    test('get accepts string path', () => {
      expect(() => client.get('test/path')).not.toThrow();
      expect(() => client.get('')).not.toThrow();
    });

    test('resolve accepts string input', () => {
      expect(() => client.resolve('test {{secret:path}}')).not.toThrow();
      expect(() => client.resolve('')).not.toThrow();
    });

    test('exists accepts string path', () => {
      expect(() => client.exists('test/path')).not.toThrow();
      expect(() => client.exists('')).not.toThrow();
    });

    test('list accepts string prefix', () => {
      expect(() => client.list('')).not.toThrow();
      expect(() => client.list('aws/')).not.toThrow();
    });

    test('requestAccess accepts path, reason, and optional duration', () => {
      expect(() => client.requestAccess('path', 'reason')).not.toThrow();
      expect(() => client.requestAccess('path', 'reason', 300)).not.toThrow();
      expect(() => client.requestAccess('path', 'reason', null)).not.toThrow();
    });

    test('scrub accepts string output', () => {
      expect(() => client.scrub('output with secrets')).not.toThrow();
      expect(() => client.scrub('')).not.toThrow();
    });

    test('exec accepts command, args, and options', () => {
      expect(() => client.exec('ls', [], null, false, null, 30)).not.toThrow();
      expect(() => client.exec('aws', ['s3', 'ls'], '/tmp', false, null, 60)).not.toThrow();
      expect(() => client.exec('cmd', ['arg'], '/work', true, '/proj', 0)).not.toThrow();
    });
  });
});
