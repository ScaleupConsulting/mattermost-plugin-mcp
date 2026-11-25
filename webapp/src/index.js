// Mattermost's login page returns to its redirect_to with a client-side route change, which the
// single-page app cannot render for a server page such as this plugin's consent screen. This
// bundle turns that route change into a real page load.
(function () {
    const PLUGIN_ID = 'com.scaleupconsulting.mcp';
    const PLUGIN_PATH = '/plugins/' + PLUGIN_ID + '/';

    /**
     * Reloads the page when the app has routed itself to one of this plugin's server pages,
     * so the server renders it. Exists because the login redirect never reaches the server.
     * @returns {void}
     */
    function loadServerPageIfRouted() {
        if (window.location.pathname.indexOf(PLUGIN_PATH) !== -1) {
            window.location.reload();
        }
    }

    /**
     * Wraps a History method so every client-side navigation is checked afterwards.
     * @param {'pushState'|'replaceState'} name - the History method to wrap
     * @returns {Function} the original method, for restoring on uninitialize
     */
    function watch(name) {
        const original = window.history[name];
        window.history[name] = function (...args) {
            const result = original.apply(this, args);
            loadServerPageIfRouted();
            return result;
        };
        return original;
    }

    class Plugin {
        /**
         * Checks the current route at load and on every later navigation.
         * @returns {void}
         */
        initialize() {
            this.originals = {pushState: watch('pushState'), replaceState: watch('replaceState')};
            window.addEventListener('popstate', loadServerPageIfRouted);
            loadServerPageIfRouted();
        }

        /**
         * Restores the History methods when the plugin is disabled.
         * @returns {void}
         */
        uninitialize() {
            window.history.pushState = this.originals.pushState;
            window.history.replaceState = this.originals.replaceState;
            window.removeEventListener('popstate', loadServerPageIfRouted);
        }
    }

    window.registerPlugin(PLUGIN_ID, new Plugin());
}());
