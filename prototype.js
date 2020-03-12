const http = require('http');
const secrets = require('../../../../node_modules/secrets.js-grempe/secrets.js');
const crypto = require('crypto');

// perms[sheetID]["user"]: {<owner, writer, reader>, sheet_key_under_user's_public_key}
var perms = {};

// answers[sheetID]: value_under_sheet_key
var answers = {};

// repo["user"]: [public_key, secret_under_derived, {/*recovery*/}]
// recovery["key"]: key_under_shares
// recovery["trusted_user"]: share_under_user's_public_key
var repo = {};

// these are not in fact stored in the server but rather
// are the passwords of the users the first of which are
// temporary passwords which are sent to the users to
// conplete the initialization process
var R_A; // regular user
var R_B; // owner
var R_C; // writer
var R_D; // auditor
var pwds = {};

// this enumerates the sheets in order
var currentSheet = 0;

const algorithm = 'aes-192-cbc';

// for AES CBC mode these may be stored in the database
// often prepending the ciphertext
const iv = Buffer.alloc(16, 0);


let aesEncrypt = function(plaintext, key) {
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  
  let ciphertext = cipher.update(plaintext,'utf8','hex')
  ciphertext += cipher.final('hex');
  
  return ciphertext;
}

let aesDecrypt = function(ciphertext, key) {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  
  let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext
}



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

  let secret = aesEncrypt(secretKey, derivedKey);
 
  // add the required things of A to the repo
  repo[c] = [publicKey, secret, {}];
}

/*
 * initialize the users
 */
let init = function() {
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


// get value (grade) of sheetID making sure that the current user
// has the required permissions.
// For now we pass in current_user as an argument
let get_value = function(sheetID, current_user) {
  // check if the user has permissions to access the grade
  perm = perms[sheetID][current_user][0]
  if (perm == undefined) {
    return -1;
  }
  // get the user's derived key
  let derivedKey = crypto.scryptSync(pwds[current_user], 'salt', 24);

  // use the derived key to get the secret key
  let ciphered_secret = repo[current_user][1];

  let deciphered_secret = aesDecrypt(ciphered_secret, derivedKey);

  // use it to get the sheet key
  let ciphered_sheet_key = perms[sheetID][current_user][1];
  let deciphered_sheet_key = crypto.privateDecrypt(deciphered_secret, ciphered_sheet_key);

  // and use that to get the value
  let ciphered_value = answers[sheetID];

  let deciphered_value = aesDecrypt(ciphered_value, deciphered_sheet_key)
  return deciphered_value;
}



// add permissions:
//
// check that the user which is attempting to change permissions has owner privilages
// get K_ID from perms(owner)
let add_perms = function(sheetID, userID, perm) {
  // verify that the user has permissions to change permissions
  // ie. if perms[sheetID][current_user][0] == "owner"
  // Here we assume B is the owner

  // get the user's derived key
  let derivedKey = crypto.scryptSync(R_B, 'salt', 24);
  
  // use the derived key to get the secret key
  let ciphered_secret = repo["B"][1];
 
  let deciphered_secret = aesDecrypt(ciphered_secret, derivedKey);
  
  // use it to get the sheet key
  let owner_ciphered_sheet_key = perms[sheetID]["B"][1];
  let deciphered_sheet_key = crypto.privateDecrypt(deciphered_secret, owner_ciphered_sheet_key);

  // now encrypt this key with the public key of whoever you want to add the permissions to
  let pub_u = repo[userID][0];
  let new_ciphered_sheet_key = crypto.publicEncrypt(pub_u, deciphered_sheet_key);

  // and we simply update the permissions
  perms[sheetID][userID] = [perm, new_ciphered_sheet_key];
}

// add_grade:
//
// verify has permissions to add a grade
// generate sheet_key
// for each person with permissions, add a permission to see the grade
// add the answer
// here we need the sheetID which will be assigned value and the
// non-privilaged user (student) which will be able to see it
let add_grade = function(sheetID, value, userID) {
  // verify the user has permissions to add a grade
  // generate the symmetric sheet_key
  sheet_key = crypto.randomBytes(24);

  let ciphered_value = aesEncrypt(value, sheet_key);

  // for each person with permissions, add their permission to see the grades,
  // in this baby example, say we are uploading A's grade so everyone has permissions
  perms[sheetID] = {};

  // here we suppose the owner, the writer, and the auditor automatically have
  // permission to open value. B is the owner, C is the writer, and D is the auditor
  let pub_o = repo["B"][0];
  let owner_ciphered_key = crypto.publicEncrypt(pub_o, sheet_key);
  perms[sheetID]["B"] = ["owner", owner_ciphered_key];
  
  let pub_w = repo["C"][0];
  let writer_ciphered_key = crypto.publicEncrypt(pub_w, sheet_key);
  perms[sheetID]["C"] = ["writer", writer_ciphered_key];
  
  let pub_a = repo["D"][0];
  let auditor_ciphered_key = crypto.publicEncrypt(pub_a, sheet_key);
  perms[sheetID]["D"] = ["auditor", auditor_ciphered_key];

  // the student should also get permission to see their grade
  let pub_u = repo[userID][0];
  let user_ciphered_key = crypto.publicEncrypt(pub_u, sheet_key);
  perms[sheetID][userID] = ["reader", user_ciphered_key];

  // finally, we add the answer
  answers[sheetID] = ciphered_value;
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
  let A_deciphered_secret = aesDecrypt(A_ciphered_secret, prev_derived_key);
 
  
  // hide the secret with the key derived from the user password
  let changed_password_secret = aesEncrypt(A_deciphered_secret, new_derived_key);

  repo["A"][1] = changed_password_secret;


  // Due to limitations in RSA encryption size, we share a symmetric key which encrypts the secret
  // as opposed to splitting the secret key itself
  let full_key = secrets.random(96);

  // encrypt the secret with the full key
  let secret_under_full_key = aesEncrypt(A_deciphered_secret, full_key);

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
  res.end('You should see two identical keys below, before and after share and combine.\n\n' +
    full_key + '\n' + comb + '\n\nThe secret should also be able to be uncovered from either the' +
    ' derived key or the full key split into shares\n\n\n');
}).listen(8080, '127.0.0.1');
console.log('Server running at http://127.0.0.1:8080/');

init();

add_grade(currentSheet, "50", "A");
console.log(perms);
console.log(answers);

currentSheet++;

add_perms(0, "A", "auditor");
console.log(perms);
console.log(answers);

// it is convenient to have an object which stores the passwords of the users
// for simulating purposes
pwds = {"A": R_A, "B": R_B, "C": R_C, "D": R_D};

let x = get_value(0,"B");
console.log(x);


