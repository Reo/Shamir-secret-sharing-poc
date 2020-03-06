const http = require('http');
const secrets = require('../../../node_modules/secrets.js-grempe/secrets.js');
const crypto = require('crypto');

var perms = {};
var answers = {};
var repo = {};

var R_A;
var R_B;
var R_C;
var R_D;

const algorithm = 'aes-192-cbc';
const iv = Buffer.alloc(16, 0);

let initUser = function(c, nonce){
  let publicKey;
  let secretKey;
  let derivedKey;

  // asymmetric crypto
  let keys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: ''
    }
  });
  publicKey = keys.publicKey;
  secretKey = keys.privateKey;

  // hide the secret key using the derived key
  derivedKey = crypto.scryptSync(nonce, 'salt', 24);
  
  let cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
  
  let secret = cipher.update(secretKey, 'utf8', 'hex');
  secret += cipher.final('hex');
 
  // add the required things of A to the repo
  repo[c] = [publicKey, secret, {}];
}

/*
 * initialize the users
 */
let init = function(){
  // initialize each user
  R_A = crypto.randomBytes(128);
  initUser("A", R_A);
  R_B = crypto.randomBytes(128);
  initUser("B", R_B);
  R_C = crypto.randomBytes(128);
  initUser("C", R_C);
  R_D = crypto.randomBytes(128);
  initUser("D", R_D);
}


http.createServer(function (req, res) {
  // grab the previous key simulating the user having entered it
  let prev_derived_key = crypto.scryptSync(R_A, 'salt', 24);
  
  // simulate A having chosen a new password to replace the temporary one
  let chosen_password = 'password123';
  R_A = chosen_password;
  let new_derived_key = crypto.scryptSync(chosen_password, 'salt', 24);
  
  let A_ciphered_secret = repo["A"][1];

  // decipher the secret key using the derived key from the temp password
  let decipher = crypto.createDecipheriv(algorithm, prev_derived_key, iv);
  
  let A_deciphered_secret = decipher.update(A_ciphered_secret, 'hex', 'utf8');
  A_deciphered_secret += decipher.final('utf8');
 
  
  // hide the secret with the key derived from the user password
  let cipher = crypto.createCipheriv(algorithm, new_derived_key, iv);

  let changed_password_secret = cipher.update(A_deciphered_secret, 'utf8', 'hex');
  changed_password_secret += cipher.final('hex');

  repo["A"][1] = changed_password_secret;


  // Due to limitations in RSA encryption size, we share a symmetric key which encrypts the secret
  // as opposed to splitting the secret key itself
  let full_key = secrets.random(96);

  // encrypt the secret with the full key
  cipher = crypto.createCipheriv(algorithm, full_key, iv);
  let secret_under_full_key = cipher.update(A_deciphered_secret, 'utf8', 'hex');
  secret_under_full_key += cipher.final('hex');

  // add the encrypted with full key to the repo
  repo["A"][2]["Key"] = secret_under_full_key;

  // encrypt the shares of the key under the trusted 3 people public keys and store in repo
  let shares = secrets.share(full_key, 3, 2);
  let comb = secrets.combine( shares );
  
  // store the shares in the repo
  // to do so we get the respective public keys to encrypt
  let pub_B = repo["B"][0];
  let buff_share_0 = Buffer.from(shares[0]);
  let cipher_share_0 = crypto.publicEncrypt(pub_B, buff_share_0);
  repo["A"][2]["B"] = cipher_share_0;
  
  let pub_C = repo["C"][0];
  let buff_share_1 = Buffer.from(shares[1]);
  let cipher_share_1 = crypto.publicEncrypt(pub_B, buff_share_1);
  repo["A"][2]["C"] = cipher_share_1;
  
  let pub_D = repo["D"][0];
  let buff_share_2 = Buffer.from(shares[2]);
  let cipher_share_2 = crypto.publicEncrypt(pub_B, buff_share_2);
  repo["A"][2]["D"] = cipher_share_2;

  res.writeHead(200, {'Content-Type': 'text/plain'});
  // res.end('Boo!');
  res.end('You should see two identical keys below, before and after share and combine.\n\n' +
    full_key + '\n' + comb + '\n\nThe secret should also be able to be uncovered from either the' +
    ' derived key or the full key split into shares\n\n\n');
}).listen(8080, '127.0.0.1');
console.log('Server running at http://127.0.0.1:8080/');


init();

