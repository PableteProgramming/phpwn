<?php
function checkAuth() {
    // pretend auth check
}
function protectedAction() {
    checkAuth();
    file_put_contents('/tmp/ok1.txt', 'fine');
}
protectedAction();
