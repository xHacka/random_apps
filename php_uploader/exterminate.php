
<?php

include_once "config.php";

if (isset($_GET['id'])) {
    $files = scandir($UPLOAD_DIR);
    foreach ($files as $file) {
        // if (strstr($file, $_GET['id'])) {
        if ($file === $_GET['id']) {
            unlink("$UPLOAD_DIR/$file");
            break;
        }
    }
}

header('Location: /show.php');