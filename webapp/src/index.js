// Mattermost's login page returns to its redirect_to with a client-side route change, which the
// single-page app cannot render for a server page such as this plugin's consent screen. This
// bundle turns that route change into a real page load, and adds an app bar icon that opens the
// connect page.
(function () {
    const PLUGIN_ID = 'com.scaleupconsulting.mcp';
    const PLUGIN_PATH = '/plugins/' + PLUGIN_ID + '/';
    const ICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' +
        '<rect width="24" height="24" rx="6" fill="#1c58d9"/>' +
        '<path d="M12 4.5l1.9 5.6 5.6 1.9-5.6 1.9-1.9 5.6-1.9-5.6-5.6-1.9 5.6-1.9z" fill="#fff"/></svg>';
    const ICON_URL = 'data:image/svg+xml;base64,' + window.btoa(ICON_SVG);

    /**
     * Opens the connect page in a new tab, so Mattermost stays open beside the steps.
     * Exists as the app bar icon's action.
     * @returns {void}
     */
    function openConnectPage() {
        window.open((window.basename || '') + PLUGIN_PATH + 'connections', '_blank', 'noopener');
    }

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
         * Adds the app bar icon, and checks the current route at load and on every later navigation.
         * @param {object} registry - the Mattermost plugin registry
         * @returns {void}
         */
        initialize(registry) {
            registry.registerAppBarComponent({iconUrl: ICON_URL, action: openConnectPage, tooltipText: 'Connect an AI assistant'});
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
