# Многопоточный поиск и удаление дубликатов файлов (PowerShell 7+)
param(
    [string]$FolderPath = "C:\Your\Folder\Path",
    [int]$ThreadCount = 4,
    [string]$Algorithm = "MD5",
    [string]$OutputCSV = "duplicates_report.csv",
    [switch]$IncludeDetails,
    [switch]$AutoDelete,
    [switch]$PreviewOnly,
    [switch]$BackupBeforeDelete,
    [string]$BackupPath = "Backup_Duplicates",
    [switch]$SkipAccessErrors
)

# Функция для логирования с исправленной обработкой цветов
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    
    # Преобразуем строку цвета в допустимое значение ConsoleColor
    $consoleColor = switch ($Color) {
        "Black" { [ConsoleColor]::Black }
        "DarkBlue" { [ConsoleColor]::DarkBlue }
        "DarkGreen" { [ConsoleColor]::DarkGreen }
        "DarkCyan" { [ConsoleColor]::DarkCyan }
        "DarkRed" { [ConsoleColor]::DarkRed }
        "DarkMagenta" { [ConsoleColor]::DarkMagenta }
        "DarkYellow" { [ConsoleColor]::DarkYellow }
        "Gray" { [ConsoleColor]::Gray }
        "DarkGray" { [ConsoleColor]::DarkGray }
        "Blue" { [ConsoleColor]::Blue }
        "Green" { [ConsoleColor]::Green }
        "Cyan" { [ConsoleColor]::Cyan }
        "Red" { [ConsoleColor]::Red }
        "Magenta" { [ConsoleColor]::Magenta }
        "Yellow" { [ConsoleColor]::Yellow }
        "White" { [ConsoleColor]::White }
        default { [ConsoleColor]::White } # Значение по умолчанию
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Используем правильный тип цвета
    Write-Host $logMessage -ForegroundColor $consoleColor
    
    # Добавляем в лог-файл
    $logMessage | Out-File -FilePath "duplicates_search.log" -Append -Encoding UTF8
}

# Функция для безопасного получения файлов
function Get-FilesSafely {
    param([string]$Path)
    
    $allFiles = @()
    $accessErrors = @()
    
    try {
        # Получаем файлы в корневой папке
        $rootFiles = Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue
        $allFiles += $rootFiles
        Write-Log "Найдено файлов в корневой папке: $($rootFiles.Count)" "INFO" "Gray"
        
        # Рекурсивно обходим подпапки
        $subfolders = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
        Write-Log "Найдено подпапок: $($subfolders.Count)" "INFO" "Gray"
        
        foreach ($folder in $subfolders) {
            try {
                Write-Log "Обработка папки: $($folder.FullName)" "DEBUG" "Gray"
                $folderFiles = Get-ChildItem -Path $folder.FullName -File -Recurse -ErrorAction Stop
                $allFiles += $folderFiles
                Write-Log "  Найдено файлов: $($folderFiles.Count)" "DEBUG" "Gray"
            }
            catch [System.UnauthorizedAccessException] {
                $errorMsg = "Отказано в доступе к папке: $($folder.FullName)"
                Write-Log $errorMsg "WARNING" "Yellow"
                $accessErrors += $errorMsg
                continue
            }
            catch [System.IO.DirectoryNotFoundException] {
                $errorMsg = "Папка не найдена: $($folder.FullName)"
                Write-Log $errorMsg "WARNING" "Yellow"
                $accessErrors += $errorMsg
                continue
            }
            catch {
                $errorMsg = "Ошибка доступа к папке $($folder.FullName): $($_.Exception.Message)"
                Write-Log $errorMsg "WARNING" "Yellow"
                $accessErrors += $errorMsg
                continue
            }
        }
    }
    catch {
        Write-Log "Ошибка при доступе к корневой папке: $($_.Exception.Message)" "ERROR" "Red"
        return @(), @("Ошибка корневой папки: $($_.Exception.Message)")
    }
    
    return $allFiles, $accessErrors
}

# Функция для создания резервной копии
function Backup-File {
    param([string]$FilePath)
    
    try {
        $backupDir = Join-Path (Get-Location) $BackupPath
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }
        
        $relativePath = $FilePath -replace '[^\w\.-]', '_'
        $backupFile = Join-Path $backupDir "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$relativePath"
        
        Copy-Item -Path $FilePath -Destination $backupFile -Force
        return $backupFile
    }
    catch {
        Write-Log "Ошибка резервного копирования: $FilePath - $($_.Exception.Message)" "ERROR" "Red"
        return $null
    }
}

# Функция для безопасного удаления
function Remove-DuplicateFile {
    param(
        [string]$FilePath,
        [string]$OriginalPath,
        [bool]$Preview,
        [bool]$Backup
    )
    
    $result = [PSCustomObject]@{
        FilePath = $FilePath
        OriginalPath = $OriginalPath
        Status = ""
        BackupPath = ""
        Error = ""
        SizeMB = 0
    }
    
    try {
        # Проверяем существование файла
        if (-not (Test-Path $FilePath)) {
            $result.Status = "NOT_FOUND"
            $result.Error = "Файл не существует"
            return $result
        }
        
        $fileItem = Get-Item $FilePath
        $result.SizeMB = [math]::Round($fileItem.Length/1MB, 2)
        
        # Создаем резервную копию если нужно
        if ($Backup) {
            $backupFile = Backup-File -FilePath $FilePath
            if ($backupFile) {
                $result.BackupPath = $backupFile
                $result.Status = "BACKUP_CREATED"
            } else {
                $result.Status = "BACKUP_FAILED"
                $result.Error = "Не удалось создать резервную копию"
                return $result
            }
        }
        
        # Удаляем или предпросмотр
        if ($Preview -or $PreviewOnly) {
            $result.Status = "PREVIEW"
        } else {
            Remove-Item -Path $FilePath -Force -ErrorAction Stop
            if (Test-Path $FilePath) {
                $result.Status = "DELETE_FAILED"
                $result.Error = "Файл не был удален"
            } else {
                $result.Status = "DELETED"
            }
        }
    }
    catch {
        $result.Status = "ERROR"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Основной скрипт
Write-Log "Запуск многопоточного поиска и удаления дубликатов (PowerShell 7+)..." "INFO" "Yellow"
Write-Log "Папка: $FolderPath" "INFO" "Gray"
Write-Log "Потоков: $ThreadCount" "INFO" "Gray"
Write-Log "Алгоритм: $Algorithm" "INFO" "Gray"
Write-Log "Автоудаление: $AutoDelete" "INFO" "Gray"
Write-Log "Предпросмотр: $PreviewOnly" "INFO" "Gray"
Write-Log "Резервная копия: $BackupBeforeDelete" "INFO" "Gray"
Write-Log "Пропуск ошибок доступа: $SkipAccessErrors" "INFO" "Gray"

# Проверяем существование папки
if (-not (Test-Path $FolderPath)) {
    Write-Log "Папка не найдена: $FolderPath" "ERROR" "Red"
    exit 1
}

# Безопасное получение файлов
Write-Log "Поиск файлов (с обработкой ошибок доступа)..." "INFO" "Yellow"
$files, $accessErrors = Get-FilesSafely -Path $FolderPath

$totalFiles = $files.Count

if ($totalFiles -eq 0) {
    Write-Log "Доступные файлы не найдены" "WARNING" "Yellow"
    if ($accessErrors.Count -gt 0) {
        Write-Log "Были ошибки доступа к некоторым папкам" "WARNING" "Yellow"
    }
    exit 0
}

Write-Log "Найдено доступных файлов для обработки: $totalFiles" "INFO" "Green"

if ($accessErrors.Count -gt 0) {
    Write-Log "Обнаружены ошибки доступа к $($accessErrors.Count) папкам" "WARNING" "Yellow"
    if ($IncludeDetails) {
        $accessErrors | ForEach-Object { Write-Log "  $_" "WARNING" "DarkYellow" }
    }
}

# Многопоточное вычисление хешей
Write-Log "Запуск многопоточной обработки в $ThreadCount потоках..." "INFO" "Yellow"

# Используем ForEach-Object -Parallel с inline функцией
$fileHashes = $files | ForEach-Object -Parallel {
    $file = $_
    $algorithm = $using:Algorithm
    
    # Inline функция для вычисления хеша
    function Get-FileHashInThread {
        param(
            [string]$FilePath,
            [string]$HashAlgorithm
        )
        try {
            $file = Get-Item $FilePath -ErrorAction Stop
            $hash = Get-FileHash -Path $FilePath -Algorithm $HashAlgorithm -ErrorAction Stop
            return @{
                Path = $file.FullName
                Hash = $hash.Hash
                Size = $file.Length
                Name = $file.Name
                CreationTime = $file.CreationTime
                LastWriteTime = $file.LastWriteTime
                Directory = $file.DirectoryName
                Success = $true
            }
        }
        catch [System.UnauthorizedAccessException] {
            return @{
                Path = $FilePath
                Hash = ""
                Size = 0
                Name = ""
                CreationTime = Get-Date
                LastWriteTime = Get-Date
                Directory = ""
                Success = $false
                Error = "Отказано в доступе"
            }
        }
        catch [System.IO.FileNotFoundException] {
            return @{
                Path = $FilePath
                Hash = ""
                Size = 0
                Name = ""
                CreationTime = Get-Date
                LastWriteTime = Get-Date
                Directory = ""
                Success = $false
                Error = "Файл не найден"
            }
        }
        catch {
            return @{
                Path = $FilePath
                Hash = ""
                Size = 0
                Name = ""
                CreationTime = Get-Date
                LastWriteTime = Get-Date
                Directory = ""
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Вызываем функцию
    Get-FileHashInThread -FilePath $file.FullName -HashAlgorithm $algorithm
} -ThrottleLimit $ThreadCount

Write-Log "Многопоточная обработка завершена" "INFO" "Green"

# Обрабатываем результаты
$validHashes = $fileHashes | Where-Object { $_.Success -eq $true }
$failedHashes = $fileHashes | Where-Object { $_.Success -eq $false }

$processedFiles = $validHashes.Count
$failedFiles = $failedHashes.Count

Write-Log "Успешно обработано файлов: $processedFiles из $totalFiles" "INFO" "Green"

if ($failedFiles -gt 0) {
    Write-Log "Не удалось обработать файлов: $failedFiles" "WARNING" "Yellow"
    if ($IncludeDetails) {
        $failedGroups = $failedHashes | Group-Object Error
        $failedGroups | ForEach-Object { 
            Write-Log "  $($_.Name): $($_.Count) файлов" "WARNING" "DarkYellow" 
        }
    }
}

if ($processedFiles -eq 0) {
    Write-Log "Нет доступных файлов для анализа" "WARNING" "Yellow"
    exit 0
}

# Преобразуем в объекты для группировки
$fileObjects = $validHashes | ForEach-Object {
    [PSCustomObject]@{
        Path = $_.Path
        Hash = $_.Hash
        Size = $_.Size
        Name = $_.Name
        CreationTime = $_.CreationTime
        LastWriteTime = $_.LastWriteTime
        Directory = $_.Directory
    }
}

# Группируем по хешу и находим дубликаты
Write-Log "Поиск дубликатов..." "INFO" "Yellow"
$hashGroups = $fileObjects | Group-Object Hash | Where-Object Count -gt 1

if ($hashGroups.Count -gt 0) {
    Write-Log "Найдено групп дубликатов: $($hashGroups.Count)" "INFO" "Cyan"
    
    # Создаем детальный отчет для CSV
    $report = @()
    $totalSaved = 0
    $totalDuplicates = 0
    $groupNumber = 0
    
    foreach ($group in $hashGroups) {
        $groupNumber++
        $sortedFiles = $group.Group | Sort-Object CreationTime
        $original = $sortedFiles[0]
        $copies = $sortedFiles[1..($sortedFiles.Count-1)]
        
        Write-Log "Группа #$groupNumber : $($group.Count) файлов ($([math]::Round($original.Size/1MB, 2)) MB)" "INFO" "White"
        
        # Добавляем оригинал в отчет
        $report += [PSCustomObject]@{
            GroupNumber = $groupNumber
            FilePath = $original.Path
            FileName = $original.Name
            FileSizeMB = [math]::Round($original.Size/1MB, 2)
            FileSizeBytes = $original.Size
            Hash = $original.Hash
            Status = "ORIGINAL"
            CreationTime = $original.CreationTime
            LastWriteTime = $original.LastWriteTime
            Directory = $original.Directory
            DuplicateGroupSize = $group.Count
            TotalDuplicateSizeMB = [math]::Round(($original.Size * ($group.Count - 1))/1MB, 2)
            Action = "KEEP"
        }
        
        # Добавляем дубликаты в отчет
        foreach ($copy in $copies) {
            $totalDuplicates++
            $totalSaved += $copy.Size
            
            $report += [PSCustomObject]@{
                GroupNumber = $groupNumber
                FilePath = $copy.Path
                FileName = $copy.Name
                FileSizeMB = [math]::Round($copy.Size/1MB, 2)
                FileSizeBytes = $copy.Size
                Hash = $copy.Hash
                Status = "DUPLICATE"
                CreationTime = $copy.CreationTime
                LastWriteTime = $copy.LastWriteTime
                Directory = $copy.Directory
                DuplicateGroupSize = $group.Count
                TotalDuplicateSizeMB = [math]::Round(($copy.Size * ($group.Count - 1))/1MB, 2)
                Action = "DELETE"
            }
            
            if ($IncludeDetails) {
                Write-Log "  ДУБЛИКАТ: $($copy.Path)" "INFO" "Red"
            }
        }
    }
    
    # Вывод итоговой статистики
    Write-Log ("=" * 60) "INFO" "Cyan"
    Write-Log "ИТОГОВАЯ СТАТИСТИКА:" "INFO" "Yellow"
    Write-Log "Групп дубликатов: $($hashGroups.Count)" "INFO" "White"
    Write-Log "Всего файлов-дубликатов: $totalDuplicates" "INFO" "White"
    Write-Log "Общий размер дубликатов: $([math]::Round($totalSaved/1MB, 2)) MB" "INFO" "Magenta"
    Write-Log "Экономия места при удалении: $([math]::Round($totalSaved/1MB, 2)) MB" "INFO" "Green"
    
    # Экспорт в CSV
    try {
        $report | Export-Csv -Path $OutputCSV -Encoding UTF8 -NoTypeInformation
        Write-Log "Отчет сохранен в: $OutputCSV" "INFO" "Green"
        Write-Log "Записей в отчете: $($report.Count)" "INFO" "Gray"
        
        # Создаем сводный отчет
        $summary = $hashGroups | ForEach-Object {
            $originalFile = $_.Group | Sort-Object CreationTime | Select-Object -First 1
            [PSCustomObject]@{
                GroupNumber = $hashGroups.IndexOf($_) + 1
                FilesInGroup = $_.Count
                OriginalFile = $originalFile.Path
                FileSizeMB = [math]::Round($originalFile.Size/1MB, 2)
                TotalWastedSpaceMB = [math]::Round(($originalFile.Size * ($_.Count - 1))/1MB, 2)
                Hash = $originalFile.Hash
            }
        }
        $summary | Export-Csv -Path "duplicates_summary.csv" -Encoding UTF8 -NoTypeInformation
        Write-Log "Сводный отчет сохранен в: duplicates_summary.csv" "INFO" "Green"
    }
    catch {
        Write-Log "Ошибка при сохранении CSV: $($_.Exception.Message)" "ERROR" "Red"
    }
    
	# УДАЛЕНИЕ ДУБЛИКАТОВ
	if ($AutoDelete -and -not $PreviewOnly) {
		Write-Log ("=" * 60) "INFO" "Cyan"
		Write-Log "ЗАПУСК ПРОЦЕССА УДАЛЕНИЯ ДУБЛИКАТОВ..." "INFO" "Yellow"
		
		# Получаем файлы для удаления из отчета
		$filesToDelete = $report | Where-Object { $_.Action -eq "DELETE" }
		
		if ($filesToDelete.Count -eq 0) {
			Write-Log "Нет файлов для удаления" "INFO" "Yellow"
		} else {
			Write-Log "Найдено файлов для удаления: $($filesToDelete.Count)" "INFO" "Yellow"
			
			# Расчет общего размера с проверкой на null
			$totalSizeMB = 0
			$sizeSum = $filesToDelete | Where-Object { $_.FileSizeBytes -ne $null } | Measure-Object -Property FileSizeBytes -Sum
			if ($sizeSum.Sum -ne $null) {
				$totalSizeMB = [math]::Round($sizeSum.Sum / 1MB, 2)
			}
			Write-Log "Общий размер: $totalSizeMB MB" "INFO" "Magenta"
			
			# Запрос подтверждения
			$confirmation = Read-Host "Вы уверены, что хотите удалить $($filesToDelete.Count) файлов? (y/N)"
			if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
				Write-Log "Удаление отменено пользователем" "INFO" "Yellow"
				exit 0
			}
			
			# Удаляем файлы
			$deleteResults = @()
			$deleteCounter = 0
			$successCount = 0
			$errorCount = 0
			$backupCount = 0
			
			foreach ($fileToDelete in $filesToDelete) {
				$deleteCounter++
				$percent = [math]::Round(($deleteCounter / $filesToDelete.Count) * 100, 2)
				
				# БЕЗОПАСНЫЙ CurrentOperation с проверкой на null
				$fileName = if ($fileToDelete.FilePath -and (Test-Path $fileToDelete.FilePath)) {
					Split-Path $fileToDelete.FilePath -Leaf
				} else {
					"неизвестный файл"
				}
				
				Write-Progress -Activity "Удаление дубликатов" -Status "Удалено: $deleteCounter из $($filesToDelete.Count)" -PercentComplete $percent -CurrentOperation "Файл: $fileName"
				
				# Находим оригинал для этой группы
				$originalFile = $report | Where-Object { 
					$_.GroupNumber -eq $fileToDelete.GroupNumber -and $_.Status -eq "ORIGINAL" 
				} | Select-Object -First 1
				
				# Проверяем существование файла перед удалением
				if (-not $fileToDelete.FilePath -or -not (Test-Path $fileToDelete.FilePath)) {
					$result = [PSCustomObject]@{
						FilePath = $fileToDelete.FilePath
						Status = "ERROR"
						Error = "Файл не существует"
						SizeMB = 0
						Timestamp = Get-Date
					}
					Write-Log "ОШИБКА УДАЛЕНИЯ: $($fileToDelete.FilePath) - Файл не существует" "ERROR" "Red"
					$errorCount++
				} else {
					try {
						$result = Remove-DuplicateFile -FilePath $fileToDelete.FilePath -OriginalPath $originalFile.FilePath -Preview $false -Backup $BackupBeforeDelete
						
						if ($result.Status -eq "DELETED") {
							Write-Log "УДАЛЕНО: $($fileToDelete.FilePath)" "INFO" "Green"
							$successCount++
						} elseif ($result.Status -eq "BACKUP_CREATED") {
							Write-Log "УДАЛЕНО (с бэкапом): $($fileToDelete.FilePath)" "INFO" "Blue"
							$successCount++
							$backupCount++
						} else {
							Write-Log "ОШИБКА УДАЛЕНИЯ: $($fileToDelete.FilePath) - $($result.Error)" "ERROR" "Red"
							$errorCount++
						}
					} catch {
						$result = [PSCustomObject]@{
							FilePath = $fileToDelete.FilePath
							Status = "ERROR"
							Error = $_.Exception.Message
							SizeMB = 0
							Timestamp = Get-Date
						}
						Write-Log "ОШИБКА УДАЛЕНИЯ: $($fileToDelete.FilePath) - $($_.Exception.Message)" "ERROR" "Red"
						$errorCount++
					}
				}
				
				$deleteResults += $result
			}
			
			Write-Progress -Activity "Удаление дубликатов" -Completed
			
			# Статистика удаления
			Write-Log ("=" * 60) "INFO" "Cyan"
			Write-Log "РЕЗУЛЬТАТЫ УДАЛЕНИЯ:" "INFO" "Yellow"
			Write-Log "Успешно удалено: $successCount файлов" "INFO" "Green"
			Write-Log "С ошибками: $errorCount файлов" "INFO" "Red"
			if ($BackupBeforeDelete) {
				Write-Log "Создано резервных копий: $backupCount файлов" "INFO" "Blue"
			}
			
			# Экспорт результатов удаления
			try {
				if ($deleteResults.Count -gt 0) {
					$deleteResults | Export-Csv -Path "deletion_results.csv" -Encoding UTF8 -NoTypeInformation
					Write-Log "Отчет об удалении сохранен в: deletion_results.csv" "INFO" "Green"
				}
			} catch {
				Write-Log "Ошибка при сохранении отчета удаления: $($_.Exception.Message)" "ERROR" "Red"
			}
			
			# Финальная статистика
			$freedSpace = ($deleteResults | Where-Object { 
				$_.Status -eq "DELETED" -and $_.SizeMB -ne $null 
			} | Measure-Object -Property SizeMB -Sum).Sum
			
			if ($freedSpace -eq $null) { $freedSpace = 0 }
			Write-Log "Освобождено места: $freedSpace MB" "INFO" "Green"
		}
	} elseif ($PreviewOnly) {
		Write-Log "Режим предпросмотра - удаление не выполнено" "INFO" "Yellow"
	} else {
		Write-Log "Для удаления используйте параметр -AutoDelete" "INFO" "Yellow"
	}

    
} else {
    Write-Log "Точные дубликаты не найдены" "INFO" "Green"
}

Write-Log "Работа скрипта завершена" "INFO" "Yellow"