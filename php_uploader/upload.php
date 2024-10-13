<?php

include_once "config.php";

// Check if the uploads directory exists; if not, create it
if (!is_dir($UPLOAD_DIR)) {
    if (mkdir($UPLOAD_DIR, 0777, true)) {
        // Set permissions to 755 after creating the directory
        chmod($UPLOAD_DIR, 0755);
    } else {
        die('Failed to create uploads directory');
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die('Method not supported');
}

// For drag and drop upload
if (isset($_FILES['files'])) {
    foreach ($_FILES['files']['name'] as $key => $name) {
        $filename = basename($name);
        $filename_temp = $_FILES['files']['tmp_name'][$key];
        if (strstr($filename, ".php")) {
            $filename = str_replace(".php", ".html", $filename);
            $contents = show_source($filename_temp, true);
            file_put_contents("$UPLOAD_DIR/$filename", $contents);
        } else {
            move_uploaded_file($filename_temp, "$UPLOAD_DIR/$filename");
        }
        echo 'Files uploaded successfully!';
    }
}

// For manual upload
if (isset($_POST['contents'])) {
    $contents = $_POST['contents'];
    $filename = isset($_POST['filename']) && !empty($_POST['filename']) ?
        basename($_POST['filename'])
        :
        date("Y-m-d\TH-i-s") . '-' . uniqid(10) . '.txt';

    if (strstr($filename, ".php")) {
        $filename = str_replace(".php", ".html", $filename);
        $filename_temp = "$UPLOAD_DIR/$filename.temp";
        file_put_contents($filename_temp, $contents);
        $contents = show_source($filename_temp, true);
        unlink($filename_temp);
    }
    if ($filename == '.htaccess') {
        die('Bad file');
    }
    file_put_contents("$UPLOAD_DIR/$filename", $contents);
    echo 'File uploaded successfully!';
} 