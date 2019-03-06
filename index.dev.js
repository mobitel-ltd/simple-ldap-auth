const LDAP = require('./src');

const url = process.env.LDAP_URL;
const adminPassword = process.env.LDAP_PASSWORD;
const adminDN = process.env.LDAP_DN;
const uid = process.env.USER_UID;
const password = process.env.USER_PASSWORD;
const baseDN = process.env.BASE_DN;

const ldap = new LDAP({url, adminPassword, adminDN, baseDN});

ldap.auth({uid, password});
