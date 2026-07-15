// FP_LOCALHOST_BASE_FIX — App.base synchronisé avec MISP.baseurl (/misp/ derrière nginx)
if (Configure::read('MISP.baseurl')) {
    $__bu = parse_url(Configure::read('MISP.baseurl'));
    if (!empty($__bu['path']) && $__bu['path'] !== '/') {
        $__base = rtrim($__bu['path'], '/');
        Configure::write('App.base', $__base);
        $__port = isset($__bu['port']) ? ':' . $__bu['port'] : '';
        Configure::write(
            'App.fullBaseUrl',
            ($__bu['scheme'] ?? 'https') . '://' . ($__bu['host'] ?? 'localhost') . $__port
        );
    }
}
