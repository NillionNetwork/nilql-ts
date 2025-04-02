/**
 * Functional and algebraic unit tests for primitives.
 * Test suite containing functional unit tests for the exported primitives,
 * as well as unit tests confirming algebraic relationships among primitives.
 */

import { describe, expect, test } from "vitest";
import { nilql } from "#/nilql";

/**
 * Helper function for converting an object that may contain `bigint` values
 * to JSON.
 */
function toJSON(o: object): string {
  return JSON.stringify(o, (_, v) =>
    typeof v === "bigint" ? v.toString() : v,
  );
}

/**
 * Concatenate two `Uint8Array` instances.
 */
function _concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

/**
 * Helper function for converting a large binary output from a test into a
 * short hash.
 */
async function toHashBase64(
  output: Uint8Array | Array<number>,
): Promise<string> {
  let uint8Array: Uint8Array;

  if (Array.isArray(output) && output.every((n) => typeof n === "number")) {
    const buffer = Buffer.alloc(8 * output.length);
    for (let i = 0; i < output.length; i++) {
      buffer.writeBigInt64LE(BigInt(output[i]), i * 8);
    }
    uint8Array = new Uint8Array(buffer);
  } else {
    uint8Array = output as Uint8Array;
  }

  return Buffer.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", uint8Array)),
  ).toString("base64");
}

/**
 * Helper function to compare two arrays of object keys (i.e., strings).
 */
function equalKeys(a: Array<string>, b: Array<string>): boolean {
  const zip = (a: Array<string>, b: Array<string>) =>
    a.map((k, i) => [k, b[i]]);
  return zip(a, b).every((pair) => pair[0] === pair[1]);
}

/**
 * API symbols that should be available to users upon module import.
 */
function apiNilql(): Array<string> {
  return [
    "SecretKey",
    "ClusterKey",
    "PublicKey",
    "encrypt",
    "decrypt",
    "allot",
    "unify",
  ];
}

/**
 * Test that the exported classes and functions match the expected API.
 */
describe("namespace", () => {
  test("nilql API has all methods", () => {
    expect(nilql).not.toBeNull();
    const methods = Object.getOwnPropertyNames(nilql);
    expect(methods).toEqual(expect.arrayContaining(apiNilql()));
  });
});

/**
 * Precomputed constant that can be reused to reduce running time of tests.
 */
const secretKeyForSumWithOneNode = await nilql.SecretKey.generate(
  { nodes: [{}] },
  { sum: true },
);

/**
 * Seed used for tests confirming that key generation from seeds is consistent.
 */
const seed = "012345678901234567890123456789012345678901234567890123456789";

/**
 * Tests of methods of cryptographic key classes.
 */
describe("methods of cryptographic key classes", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}] }];
  for (const cluster of clusters) {
    test("generate, dump, JSONify, and load key for store operation", async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        store: true,
      });

      const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
      const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

      const plaintext = "abc";
      const ciphertext = await nilql.encrypt(secretKey, plaintext);
      const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
      expect(decrypted).toEqual(plaintext);
    });

    test("generate, dump, JSONify, and load key for match operation", async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
      const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

      const plaintext = "abc";
      const ciphertext = await nilql.encrypt(secretKey, plaintext);
      const ciphertextViaLoaded = await nilql.encrypt(
        secretKeyLoaded,
        plaintext,
      );
      expect(ciphertextViaLoaded).toEqual(ciphertext);
    });
  }

  test("generate, dump, JSONify, and load keys for sum operation with single node", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const publicKeyObject = JSON.parse(JSON.stringify(publicKey.dump()));
    const publicKeyLoaded = nilql.PublicKey.load(publicKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(publicKeyLoaded, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("generate, dump, JSONify, and load secret key for sum operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });

    const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(secretKey, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("generate, dump, JSONify, and load cluster key for sum operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const clusterKey = await nilql.ClusterKey.generate(cluster, { sum: true });

    const clusterKeyObject = JSON.parse(JSON.stringify(clusterKey.dump()));
    const clusterKeyLoaded = nilql.ClusterKey.load(clusterKeyObject);
    expect(clusterKeyLoaded instanceof nilql.ClusterKey).toEqual(true);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(clusterKey, plaintext);
    const decrypted = await nilql.decrypt(clusterKeyLoaded, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("generate, dump, JSONify, and load secret key for sum operation with multiple nodes and threshold", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true }, 3);

    const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(secretKey, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("generate, dump, JSONify, and load cluster key for sum operation with multiple nodes and threshold", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const clusterKey = await nilql.ClusterKey.generate(
      cluster,
      { sum: true },
      3,
    );

    const clusterKeyObject = JSON.parse(JSON.stringify(clusterKey.dump()));
    const clusterKeyLoaded = nilql.ClusterKey.load(clusterKeyObject);
    expect(clusterKeyLoaded instanceof nilql.ClusterKey).toEqual(true);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(clusterKey, plaintext);
    const decrypted = await nilql.decrypt(clusterKeyLoaded, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("generate key from seed for store operation with single node", async () => {
    const secretKeyFromSeed = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
      null,
      seed,
    );
    expect(
      await toHashBase64(secretKeyFromSeed.material as Uint8Array),
    ).toStrictEqual("2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w=");

    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    expect(await toHashBase64(secretKey.material as Uint8Array)).not.toEqual(
      "2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w=",
    );
  });

  test("generate key from seed for store operation with multiple nodes", async () => {
    const secretKeyFromSeed = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { store: true },
      null,
      seed,
    );
    expect(
      await toHashBase64(secretKeyFromSeed.material as Uint8Array),
    ).toStrictEqual("2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w=");

    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { store: true },
    );
    expect(await toHashBase64(secretKey.material as Uint8Array)).not.toEqual(
      "2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w=",
    );
  });

  test("generate key from seed for match operation with single node", async () => {
    const secretKeyFromSeed = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { match: true },
      null,
      seed,
    );
    expect(
      await toHashBase64(secretKeyFromSeed.material as Uint8Array),
    ).toStrictEqual("qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4=");

    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { match: true },
    );
    expect(await toHashBase64(secretKey.material as Uint8Array)).not.toEqual(
      "qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4=",
    );
  });

  test("generate key from seed for match operation with multiple nodes", async () => {
    const secretKeyFromSeed = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { match: true },
      null,
      seed,
    );
    expect(
      await toHashBase64(secretKeyFromSeed.material as Uint8Array),
    ).toStrictEqual("qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4=");

    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { match: true },
    );
    expect(await toHashBase64(secretKey.material as Uint8Array)).not.toEqual(
      "qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4=",
    );
  });

  test("generate key from seed for sum operation with multiple nodes", async () => {
    const secretKeyFromSeed = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
      null,
      seed,
    );
    expect(
      await toHashBase64(secretKeyFromSeed.material as number[]),
    ).toStrictEqual("L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84=");

    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
    );
    expect(await toHashBase64(secretKey.material as number[])).not.toEqual(
      "L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84=",
    );
  });
});

test("generate key from seed for sum operation with multiple nodes and threshold", async () => {
  const secretKeyFromSeed = await nilql.SecretKey.generate(
    { nodes: [{}, {}, {}] },
    { sum: true },
    2,
    seed,
  );
  expect(
    await toHashBase64(secretKeyFromSeed.material as number[]),
  ).toStrictEqual("L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84=");

  const secretKey = await nilql.SecretKey.generate(
    { nodes: [{}, {}, {}] },
    { sum: true },
    2,
  );
  expect(await toHashBase64(secretKey.material as number[])).not.toEqual(
    "L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84=",
  );
});

/**
 * Tests of errors thrown by methods of cryptographic key classes.
 */
describe("errors involving methods of cryptographic key classes", () => {
  test("errors in secret key generation", async () => {
    try {
      const secretKey = await nilql.SecretKey.generate(
        { nodes: [{}] },
        { match: true, sum: true },
      );
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("operation specification must enable exactly one operation"),
      );
    }
  });

  test("errors in secret key dumping and loading", async () => {
    try {
      const secretKey = await nilql.SecretKey.generate(
        { nodes: [{}, {}, {}] },
        { sum: true },
      );
      const secretKeyObject = secretKey.dump() as {
        material: object;
        cluster: object;
        operations?: object;
      };
      nilql.SecretKey.load({
        material: secretKeyObject.material,
        cluster: secretKeyObject.cluster,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }

    try {
      const secretKey = secretKeyForSumWithOneNode;
      const secretKeyObject = secretKey.dump() as {
        material: {
          l: object;
          m: object;
          n?: object;
          g: object;
        };
        cluster: object;
        operations: object;
      };
      secretKeyObject.material.n = undefined;
      nilql.SecretKey.load({
        material: {
          m: secretKeyObject.material.m,
          l: secretKeyObject.material.l,
        },
        cluster: secretKeyObject.cluster,
        operations: secretKeyObject.operations,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }

    try {
      const secretKey = secretKeyForSumWithOneNode;
      const secretKeyObject = secretKey.dump() as {
        material: {
          l: object;
          m: object | number;
          n: object;
          g: object;
        };
        cluster: object;
        operations: object;
      };
      secretKeyObject.material.m = 123;
      nilql.SecretKey.load(secretKeyObject);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }

    try {
      const secretKey = secretKeyForSumWithOneNode;
      const secretKeyObject = secretKey.dump() as {
        material: {
          l: object;
          m: object;
          n: string | number;
          g: object;
        };
        cluster: object;
        operations: object;
      };
      secretKeyObject.material.n = 123;
      nilql.SecretKey.load(secretKeyObject);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }
  });

  test("errors in public key generation", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    try {
      const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
      const publicKey = await nilql.PublicKey.generate(secretKey);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("cannot create public key for supplied secret key"),
      );
    }
  });

  test("errors in public key dumping and loading", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    try {
      const publicKeyObject = publicKey.dump() as {
        material: { n: string; g: string };
        cluster?: object;
        operations: object;
      };
      nilql.PublicKey.load({
        material: publicKeyObject.material,
        operations: publicKeyObject.operations,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a public key"),
      );
    }

    try {
      const publicKeyObject = publicKey.dump() as {
        material: { n?: string; g: string };
        cluster: object;
        operations: object;
      };
      nilql.PublicKey.load({
        material: { g: publicKeyObject.material.g },
        cluster: publicKeyObject.cluster,
        operations: publicKeyObject.operations,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a public key"),
      );
    }

    try {
      const publicKeyObject = publicKey.dump() as {
        material: { n: string; g: string | number };
        cluster: object;
        operations: object;
      };
      publicKeyObject.material.g = 123;
      nilql.PublicKey.load(publicKeyObject);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a public key"),
      );
    }
  });
});

/**
 * Tests of the functional and algebraic properties of encryption/decryption functions.
 */
describe("encryption and decryption functions", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}] }];
  for (const cluster of clusters) {
    test(`encryption and decryption for store operation (${cluster.nodes.length})`, async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        store: true,
      });

      const plaintextNumber = 123;
      const ciphertextFromNumber = await nilql.encrypt(
        secretKey,
        plaintextNumber,
      );
      const decryptedFromNumber = Number(
        await nilql.decrypt(secretKey, ciphertextFromNumber),
      );
      expect(decryptedFromNumber).toEqual(plaintextNumber);

      const plaintextBigInt = BigInt(123);
      const ciphertextFromBigInt = await nilql.encrypt(
        secretKey,
        plaintextBigInt,
      );
      const decryptedFromBigInt = (await nilql.decrypt(
        secretKey,
        ciphertextFromBigInt,
      )) as bigint;
      expect(decryptedFromBigInt).toEqual(plaintextBigInt);

      const plaintextString = "abc";
      const ciphertextFromString = await nilql.encrypt(
        secretKey,
        plaintextString,
      );
      const decryptedFromString = (await nilql.decrypt(
        secretKey,
        ciphertextFromString,
      )) as string;
      expect(decryptedFromString).toEqual(plaintextString);

      const plaintextBinary = new Uint8Array([1, 2, 3]);
      const ciphertextFromBinary = await nilql.encrypt(
        secretKey,
        plaintextBinary,
      );
      const decryptedFromBinary = (await nilql.decrypt(
        secretKey,
        ciphertextFromBinary,
      )) as Uint8Array;
      expect(decryptedFromBinary).toEqual(plaintextBinary);
    });

    test(`encryption and decryption for large store operation (${cluster.nodes.length})`, async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        store: true,
      });

      const plaintextString = `
      Bart Simpson is a fictional character in the American animated television series The Simpsons
      who is part of the Simpson family. Described as one of the 100 most important people of the
      20th century by Time, Bart was created and designed by Matt Groening in James L. Brooks's
      office. Bart, alongside the rest of the family, debuted in the short 'Good Night' on The
      Tracey Ullman Show on April 19, 1987. Two years later, the family received their own series,
      which premiered on Fox on December 17, 1989. Born on April Fools' Day according to Groening,
      Bart is ten years old; he is the eldest child and only son of Homer and Marge Simpson, and
      has two sisters, Lisa and Maggie. Voiced by Nancy Cartwright (pictured), Bart is known for
      his mischievousness, rebelliousness, and disrespect for authority, as well as his prank calls
      to Moe, chalkboard gags in the opening sequence, and catchphrases. Bart is considered an
      iconic fictional television character of the 1990s and has been called an American cultural icon.`;
      const ciphertextFromString = await nilql.encrypt(
        secretKey,
        plaintextString,
      );
      const decryptedFromString = (await nilql.decrypt(
        secretKey,
        ciphertextFromString,
      )) as string;
      expect(decryptedFromString).toEqual(plaintextString);
    });

    test(`encryption of number for match operation (${cluster.nodes.length})`, async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const plaintextNumber = 123;
      const ciphertextFromNumber = (await nilql.encrypt(
        secretKey,
        plaintextNumber,
      )) as string;

      const plaintextBigInt = BigInt(123);
      const ciphertextFromBigInt = (await nilql.encrypt(
        secretKey,
        plaintextBigInt,
      )) as string;

      expect(ciphertextFromNumber).toEqual(ciphertextFromBigInt);
    });

    test("encryption of string for match operation", async () => {
      const secKeyOne = await nilql.SecretKey.generate(cluster, {
        match: true,
      });
      const secKeyTwo = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const plaintextOne = "ABC";
      const plaintextTwo = "ABC";
      const plaintextThree = "abc";
      const ciphertextOne = await nilql.encrypt(secKeyOne, plaintextOne);
      const ciphertextTwo = await nilql.encrypt(secKeyOne, plaintextTwo);
      const ciphertextThree = await nilql.encrypt(secKeyOne, plaintextThree);
      const ciphertextFour = await nilql.encrypt(secKeyTwo, plaintextThree);
      expect(ciphertextTwo).toEqual(ciphertextOne);
      expect(ciphertextThree).not.toEqual(ciphertextOne);
      expect(ciphertextFour).not.toEqual(ciphertextThree);
    });

    test("encryption of binary data for match operation", async () => {
      const secKeyOne = await nilql.SecretKey.generate(cluster, {
        match: true,
      });
      const secKeyTwo = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const plaintextOne = new Uint8Array([1, 2, 3]);
      const plaintextTwo = new Uint8Array([1, 2, 3]);
      const plaintextThree = new Uint8Array([4, 5, 6, 7, 8, 9]);
      const ciphertextOne = await nilql.encrypt(secKeyOne, plaintextOne);
      const ciphertextTwo = await nilql.encrypt(secKeyOne, plaintextTwo);
      const ciphertextThree = await nilql.encrypt(secKeyOne, plaintextThree);
      const ciphertextFour = await nilql.encrypt(secKeyTwo, plaintextThree);
      expect(ciphertextTwo).toEqual(ciphertextOne);
      expect(ciphertextThree).not.toEqual(ciphertextOne);
      expect(ciphertextFour).not.toEqual(ciphertextThree);
    });
  }

  test("encryption and decryption for sum operation with single node", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      publicKey,
      plaintextNumber,
    );
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    );
    expect(decryptedFromNumber).toEqual(BigInt(plaintextNumber));

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      publicKey,
      plaintextBigInt,
    );
    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    );
    expect(decryptedFromBigInt).toEqual(plaintextBigInt);
  });

  test("encryption and decryption for sum operation with multiple nodes", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
    );

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      secretKey,
      plaintextNumber,
    );
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    );
    expect(decryptedFromNumber).toEqual(BigInt(plaintextNumber));

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      secretKey,
      plaintextBigInt,
    );
    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    );
    expect(decryptedFromBigInt).toEqual(plaintextBigInt);
  });

  test("encryption and decryption for sum operation with multiple nodes and threshold", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
      3,
    );

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      secretKey,
      plaintextNumber,
    );
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    );
    expect(decryptedFromNumber).toEqual(BigInt(plaintextNumber));

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      secretKey,
      plaintextBigInt,
    );
    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    );
    expect(decryptedFromBigInt).toEqual(plaintextBigInt);
  });

  test("encryption and decryption for sum operation with multiple nodes and no failure", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
      3,
    );

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      secretKey,
      plaintextNumber,
    );
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    );
    expect(decryptedFromNumber).toEqual(BigInt(plaintextNumber));

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      secretKey,
      plaintextBigInt,
    );
    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    );
    expect(decryptedFromBigInt).toEqual(plaintextBigInt);
  });

  test("encryption and decryption for sum operation with multiple nodes and one failure", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] }, // 3 nodes
      { sum: true },
      2,
    );

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      secretKey,
      plaintextNumber,
    );

    // Simulate a node failure by removing one share
    const partialCiphertext = ciphertextFromNumber.slice(1); // Removing the first share
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      partialCiphertext,
    );
    expect(decryptedFromNumber).toEqual(BigInt(plaintextNumber));

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      secretKey,
      plaintextBigInt,
    );

    // Simulate failure again
    const partialCiphertextBigInt = ciphertextFromBigInt.slice(1);

    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      partialCiphertextBigInt,
    );
    expect(decryptedFromBigInt).toEqual(plaintextBigInt);
  });
});

/**
 * Tests of the portable representation of ciphertexts.
 */
describe("portable representation of ciphertexts", () => {
  test("secret share representation for store operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const clusterKey = await nilql.ClusterKey.generate(cluster, {
      store: true,
    });
    const plaintext = "abc";
    const ciphertext = ["Ifkz2Q==", "8nqHOQ==", "0uLWgw=="];
    const decrypted = await nilql.decrypt(clusterKey, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("secret share representation for sum operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const clusterKey = await nilql.ClusterKey.generate(cluster, { sum: true });
    const plaintext = BigInt(123);
    const ciphertext = [456, 246, 4294967296 + 15 - 123 - 456];
    const decrypted = await nilql.decrypt(clusterKey, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("secret share representation for sum operation with multiple nodes and threshold", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const clusterKey = await nilql.ClusterKey.generate(
      cluster,
      { sum: true },
      3,
    );
    const plaintext = BigInt(123);
    const ciphertext = [
      [1, 1382717699],
      [2, 2765435275],
      [3, 4148152851],
    ];
    const decrypted = await nilql.decrypt(clusterKey, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });
});

/**
 * Tests verifying that encryption/decryption methods return expected errors.
 */
describe("errors involving encryption and decryption functions", () => {
  test("errors in encryption for store operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });

    try {
      await nilql.encrypt(secretKey, 2 ** 31 + 1);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("numeric plaintext must be a valid 32-bit signed integer"),
      );
    }

    try {
      await nilql.encrypt(secretKey, "x".repeat(4097));
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "plaintext must be possible to encode in 4096 bytes or fewer",
        ),
      );
    }
  });

  test("errors in encryption for match operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { match: true });

    try {
      await nilql.encrypt(secretKey, 2 ** 31 + 1);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("numeric plaintext must be a valid 32-bit signed integer"),
      );
    }

    try {
      await nilql.encrypt(secretKey, "x".repeat(4097));
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "plaintext must be possible to encode in 4096 bytes or fewer",
        ),
      );
    }
  });

  test("errors in encryption for sum operation", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    try {
      await nilql.encrypt(publicKey, "ABC");
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "plaintext to encrypt for sum operation must be integer number or bigint",
        ),
      );
    }

    for (const plaintext of [
      -123,
      BigInt(-123),
      (-2) ** 31,
      2 ** 31 - 1,
      -BigInt(2 ** 31),
      BigInt(2 ** 31) - BigInt(1),
    ]) {
      try {
        await nilql.encrypt(publicKey, plaintext);
      } catch (e) {
        expect(e).toStrictEqual(
          TypeError("numeric plaintext must be a valid 32-bit signed integer"),
        );
      }
    }
  });

  test("errors in decryption for store operation due to cluster size mismatch", async () => {
    const secretKeyOne = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    const secretKeyTwo = await nilql.SecretKey.generate(
      { nodes: [{}, {}] },
      { store: true },
    );
    const secretKeyThree = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { store: true },
    );

    const ciphertextOne = await nilql.encrypt(secretKeyOne, 123);
    const ciphertextTwo = await nilql.encrypt(secretKeyTwo, 123);

    try {
      await nilql.decrypt(secretKeyOne, ciphertextTwo);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "secret key requires a valid ciphertext from a single-node cluster",
        ),
      );
    }

    try {
      await nilql.decrypt(secretKeyOne, ciphertextOne);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "secret key requires a valid ciphertext from a multi-node cluster",
        ),
      );
    }

    try {
      await nilql.decrypt(secretKeyThree, ciphertextTwo);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "secret key and ciphertext must have the same associated cluster size",
        ),
      );
    }
  });

  test("errors in decryption for store operation due to key mismatch", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    const secretKeyAlt = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    const ciphertext = await nilql.encrypt(secretKey, 123);

    try {
      await nilql.decrypt(secretKeyAlt, ciphertext);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "cannot decrypt the supplied ciphertext using the supplied key",
        ),
      );
    }
  });

  test("errors in decryption for sum operation  due to key mismatch", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const secretKeyAlt = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { sum: true },
    );
    const publicKey = await nilql.PublicKey.generate(secretKey);
    const ciphertext = await nilql.encrypt(publicKey, 123);

    try {
      await nilql.decrypt(secretKeyAlt, ciphertext);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "cannot decrypt the supplied ciphertext using the supplied key",
        ),
      );
    }
  });
});

/**
 * Tests consisting of end-to-end workflows involving encryption/decryption.
 */
describe("end-to-end workflows involving encryption/decryption", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}, {}, {}] }];

  const plaintexts = [
    BigInt((-2) ** 31),
    BigInt(2 ** 31 - 1),
    BigInt(-1),
    BigInt(0),
    BigInt(1),
    BigInt(2),
    BigInt(3),
    "ABC",
    new Array(4095).fill("?").join(""),
  ];

  const numbers = [(-2) ** 31, -1, -3, -1, 0, 1, 3, 2 ** 31 - 1];

  for (const cluster of clusters) {
    for (const plaintext of plaintexts) {
      test("end-to-end workflow for store operation", async () => {
        const secretKey = await nilql.SecretKey.generate(cluster, {
          store: true,
        });
        const ciphertext = await nilql.encrypt(secretKey, plaintext);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(decrypted).toEqual(plaintext);
      });

      test("end-to-end workflow for match operation", async () => {
        const secretKey = await nilql.SecretKey.generate(cluster, {
          match: true,
        });
        const ciphertext = await nilql.encrypt(secretKey, plaintext);
        expect(ciphertext).not.toBeNull();
      });
    }

    for (const number of numbers) {
      test(`end-to-end workflow for sum operation: ${number}`, async () => {
        const secretKey =
          cluster.nodes.length === 1
            ? secretKeyForSumWithOneNode
            : await nilql.SecretKey.generate(cluster, {
                sum: true,
              });
        const ciphertext = await nilql.encrypt(secretKey, number);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(BigInt(decrypted as bigint)).toEqual(BigInt(number));
      });
    }
  }

  for (const number of numbers) {
    test(`end-to-end workflow for sum operation: ${number}`, async () => {
      const secretKey = secretKeyForSumWithOneNode;
      const publicKey = await nilql.PublicKey.generate(secretKey);
      const ciphertext = await nilql.encrypt(publicKey, number);
      const decrypted = await nilql.decrypt(secretKey, ciphertext);
      expect(BigInt(decrypted as bigint)).toEqual(BigInt(number));
    });
  }
});

/**
 * Tests consisting of end-to-end workflows involving secure computation.
 */
describe("end-to-end workflows involving secure computation", () => {
  test("end-to-end workflow for secure summation with a multi-node cluster", async () => {
    const secretKey = await nilql.ClusterKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
    );
    const [a0, b0, c0] = (await nilql.encrypt(secretKey, 123)) as Array<number>;
    const [a1, b1, c1] = (await nilql.encrypt(secretKey, 456)) as Array<number>;
    const [a2, b2, c2] = (await nilql.encrypt(secretKey, 789)) as Array<number>;
    const [a3, b3, c3] = [
      (a0 + a1 + a2) % (2 ** 32 + 15),
      (b0 + b1 + b2) % (2 ** 32 + 15),
      (c0 + c1 + c2) % (2 ** 32 + 15),
    ];
    const decrypted = await nilql.decrypt(secretKey, [a3, b3, c3]);
    expect(BigInt(decrypted as bigint)).toEqual(BigInt(123 + 456 + 789));
  });
});

/**
 * Tests consisting of end-to-end workflows involving secure computation.
 */
describe("end-to-end workflows involving secure computation", () => {
  test("end-to-end workflow for secure summation with a multi-node cluster and threshold", async () => {
    const secretKey = await nilql.ClusterKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
      3,
    );
    const [a0, b0, c0] = (await nilql.encrypt(secretKey, 123)) as Array<
      [number, number]
    >;
    const [a1, b1, c1] = (await nilql.encrypt(secretKey, 456)) as Array<
      [number, number]
    >;
    const [a2, b2, c2] = (await nilql.encrypt(secretKey, 789)) as Array<
      [number, number]
    >;

    const [a3, b3, c3] = nilql.shamirsAdd(
      nilql.shamirsAdd([a0, b0, c0], [a1, b1, c1]),
      [a2, b2, c2],
    );
    const decrypted = await nilql.decrypt(secretKey, [a3, b3, c3]);
    expect(BigInt(decrypted as bigint)).toEqual(BigInt(123 + 456 + 789));
  });
});

/**
 * Tests consisting of end-to-end workflows involving share allotment and unification.
 */
describe("end-to-end workflows involving share allotment and unification", () => {
  const cluster = { nodes: [{}, {}, {}] };

  test("allotment and unification of arrays for a multi-node cluster", async () => {
    const data = [12n, 34n, 56n, 78n, 90n];
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted = [];
    for (let i = 0; i < data.length; i++) {
      encrypted.push({ "%allot": await nilql.encrypt(secretKey, data[i]) });
    }
    const shares = nilql.allot(encrypted) as Array<Array<object>>;
    expect(shares.length).toEqual(3);
    expect(shares.every((share) => share.length === data.length)).toEqual(true);

    const decrypted = await nilql.unify(secretKey, shares);
    expect(decrypted).toEqual(data);
  });

  test("allotment and unification of simple objects for a multi-node cluster", async () => {
    const data: { [k: string]: bigint } = {
      a: 12n,
      b: 34n,
      c: 56n,
      d: 78n,
      e: 90n,
    };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted: { [k: string]: object } = {};
    for (const key in data) {
      encrypted[key] = { "%allot": await nilql.encrypt(secretKey, data[key]) };
    }
    const shares = nilql.allot(encrypted) as Array<Array<object>>;
    expect(shares.length).toEqual(3);

    const keys = Object.keys(data);
    expect(
      shares.every((share) => equalKeys(Object.keys(share), keys)),
    ).toEqual(true);

    const decrypted = await nilql.unify(secretKey, shares);
    expect(decrypted).toEqual(data);
  });

  test("allotment and unification of mixed objects for a multi-node cluster", async () => {
    const data: { [k: string]: [boolean, string, bigint] } = {
      a: [true, "v", 12n],
      b: [false, "w", 34n],
      c: [true, "x", 56n],
      d: [false, "y", 78n],
      e: [true, "z", 90n],
    };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted: { [k: string]: object } = {};
    for (const key in data) {
      encrypted[key] = [
        data[key][0],
        data[key][1],
        { "%allot": await nilql.encrypt(secretKey, data[key][2]) },
      ];
    }
    const shares = nilql.allot(encrypted) as Array<Array<object>>;
    expect(shares.length).toEqual(3);

    const decrypted = await nilql.unify(secretKey, shares);
    expect(toJSON(decrypted)).toEqual(toJSON(data));
  });

  test("allotment and unification of objects with nested arrays of shares for a multi-node cluster", async () => {
    const data: { [k: string]: object | null } = {
      a: [1n, [2n, 3n]],
      b: [4n, [5n, 6n]],
      c: null,
    };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted: { [k: string]: object | null } = {};
    for (const key of ["a", "b"]) {
      encrypted[key] = {
        "%allot": [
          await nilql.encrypt(secretKey, (data[key] as Array<bigint>)[0]),
          [
            await nilql.encrypt(
              secretKey,
              (data[key] as Array<Array<bigint>>)[1][0],
            ),
            await nilql.encrypt(
              secretKey,
              (data[key] as Array<Array<bigint>>)[1][1],
            ),
          ],
        ],
      };
    }
    encrypted.c = null;
    const shares = nilql.allot(encrypted) as Array<{
      [key: string]: string | object;
    }>;
    expect(shares.length).toEqual(3);

    // Introduce entries that should be ignored.
    shares[0]._created = "123";
    shares[1]._created = "456";
    shares[2]._created = "789";
    shares[0]._updated = "ABC";
    shares[1]._updated = "DEF";
    shares[2]._updated = "GHI";

    const decrypted = await nilql.unify(secretKey, shares);
    expect(toJSON(decrypted)).toEqual(toJSON(data));
  });
});
