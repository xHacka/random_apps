<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body {
            width: 100%;
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .container {
            width: fit-content;
        }
    </style>
</head>

<body>
    <div class="container">
        <h2>Uploaded Files</h2>
        <ul id="file-list">
            <?php
            include_once "config.php";

            $files = scandir($UPLOAD_DIR);
            foreach ($files as $file) {
                if ($file === '.' || $file === '..') { continue; }
                echo "<li><a href='$UPLOAD_DIR/$file'>$file</a></li>";
            }
            ?>
        </ul>
    </div>
</body>

</html>