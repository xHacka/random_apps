<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <style>.container{max-width:600px;margin:auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,.1)}.upload-area,.upload-manual{margin-bottom:20px}h1,h2{color:#333}.upload-area{border:2px dashed #08c;padding:20px;text-align:center}#file-drop-area{cursor:pointer}button,input[type=file],input[type=text],textarea{margin-top:10px;padding:10px;width:100%;box-sizing:border-box}button{background-color:#08c;color:#fff;border:none;border-radius:4px}button:hover{background-color:#057}</style>
</head>
<body>
    <div class="container">
        <h1>File Upload System</h1>
        
        <div id="upload-area" class="upload-area">
            <h2>Drag and Drop Upload</h2>
            <p>Drag and drop files here or click to upload</p>
            <input type="file" id="file-input" multiple hidden>
            <div id="file-drop-area">Drop files here...</div>
        </div>
        
        <div class="upload-manual">
            <h2>Paste Your Text Here</h2>
            <form id="manual-upload" action="upload.php" method="POST" enctype="multipart/form-data">
                <textarea name="contents" rows="10" placeholder="Paste your text here..." required></textarea>
                <input type="text" name="filename" placeholder="Enter custom name (Optional)">
                <button type="submit">Upload</button>
            </form>
        </div>

        <h2>Uploaded Files</h2>
        <ul id="file-list">
            <?php
                $files = scandir('uploads');
                foreach ($files as $file) {
                    if ($file === '.' || $file === '..') { continue; }
                    echo "<li><a href='uploads/$file'>$file</a></li>";
                }
            ?>
        </ul>
    </div>

    <script>
        document.getElementById('file-drop-area').addEventListener('click', function() { document.getElementById('file-input').click(); });
        document.getElementById('file-input').addEventListener('change', function(event) { uploadFiles(event.target.files); });
        document.getElementById('file-drop-area').addEventListener('dragover', function(event) { event.preventDefault(); });
        document.getElementById('file-drop-area').addEventListener('drop', function(event) { event.preventDefault(); uploadFiles(event.dataTransfer.files); });

        function uploadFiles(files) {
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) { formData.append('files[]', files[i]); }
            fetch('upload.php', { method: 'POST', body: formData })
            .then(response => response.text())
            .then(data => { alert(data); location.reload(); })
            .catch(error => { console.error('Error:', error); });
        }

        document.getElementById('manual-upload').addEventListener('submit', function(event) {
            event.preventDefault();
            const formdata = new FormData(this);
            console.log(...formdata)
            fetch('upload.php', { method: 'POST', body: formdata })
            .then(response => response.text())
            .then(data => { alert(data); location.reload(); })
            .catch(error => { console.error('Error:', error); });
        });
    </script>
</body>
</html>