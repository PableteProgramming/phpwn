<?php
function leakSecret() {
    file_put_contents('/tmp/leak.txt', 'secret-data');
}
leakSecret();
