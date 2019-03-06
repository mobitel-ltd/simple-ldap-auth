const ldapts = require('ldapts');

/**
  * @class
  * @classdesc Simple LDAP auth service
 */
class LdapAuthService {
/**
     * @typedef {Object} Logger logger
     * @property {Function} debug debug log
     * @property {Function} info info log
     * @property {Function} warn warn log
     * @property {Function} error error log
     */

    /**
     * @param {Object} options ldap connect options
     * @param {String} options.url ldap url
     * @param {String} options.adminPassword ldap admin password
     * @param {String} options.adminDN ldap admin DN
     * @param {String} options.baseDN base DN to search
     * @param {Function} options.LDAPLib=ldapts.Client lib to work with LDAP, by default ldapts.Client
     * @param {Logger} options.logger=defaultLogger logger object with winston like calls, by default - console
     */
    constructor({url, adminPassword, adminDN, baseDN, LDAPLib = ldapts.Client, logger = console}) {
        this.client = new LDAPLib({url});
        this.adminPassword = adminPassword;
        this.adminDN = adminDN;
        this.logger = logger;
        this.baseDN = baseDN;
    }

    /**
     * @async
     * @param {String} dn LDAP DN
     * @param {String} password LDAP DN password
     * @returns {Promise<Boolean>} resolves with true if all ok, rejects with error if not correct data to init
     */
    async _start(dn, password) {
        try {
            await this.client.bind(dn, password);
            this.logger.info('Connected to LDAP!!!');

            return true;
        } catch (error) {
            this.logger.error('Incorrect admin user credentials!!!');
            throw error;
        }
    }

    /**
     * @async
     * @param {Object} options ldap auth options
     * @param {String} options.uid uid of searching user
     * @param {String} options.password password of searching user
     */
    async auth({uid, password}) {
        try {
            await this._start(this.adminDN, this.adminPassword);

            const {searchEntries} = await this.client.search(this.baseDN, {sizeLimit: 1, filter: `(uid=${uid})`, attributes: ['dn']});
            const [userInfo] = searchEntries;
            if (!userInfo) {
                this.logger.warn('No user is found with uid "%s"!!!', uid);

                return false;
            }

            this.logger.debug('Info about user "%s" is: ', uid, userInfo);
            await this.client.bind(userInfo.dn, password);
            this.logger.info('User successfully authenticated!!!');

            return true;
        } catch (error) {
            throw error;
        } finally {
            this.client.unbind();
        }
    }
}

module.exports = LdapAuthService;
