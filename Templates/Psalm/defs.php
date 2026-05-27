<?php

class HTMLPurifier {
    /**
     * @psalm-flow ($html) -> return
     */
    public function purify(string $html, $config = null): string {}
}