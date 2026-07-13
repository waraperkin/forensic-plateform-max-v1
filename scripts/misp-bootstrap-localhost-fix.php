// FP_LOCALHOST_BASE_FIX — App.base pour localhost / hôtes sans point (regex CakePHP bootstrap)
if (Configure::read('MISP.baseurl') && !Configure::read('App.base')) {
    $__bu = parse_url(Configure::read('MISP.baseurl'));
    if (!empty($__bu['path']) && $__bu['path'] !== '/') {
        Configure::write('App.base', rtrim($__bu['path'], '/'));
        $__port = isset($__bu['port']) ? ':' . $__bu['port'] : '';
        Configure::write(
            'App.fullBaseUrl',
            ($__bu['scheme'] ?? 'https') . '://' . ($__bu['host'] ?? 'localhost') . $__port
        );
    }
}
