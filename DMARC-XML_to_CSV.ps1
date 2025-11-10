# --------------------------------------------------------------------------------------------------------------------------------------------
# Permet d'extraire les informations d'un fichier DMAC .xml, et les garde dans une matrice.
# -file_path -> chemin complet du fichier .xml
# --------------------------------------------------------------------------------------------------------------------------------------------
function Get-DMARC-data {
	param (
		[string]$file_path
	)
	
	# Rassemblement des données des fichiers xml (un par uns)
	# Chaque <record> est une colonne (donc $temp_data_array[0][0] et $temp_data_array[1][0] appartiennent au même <record>)
	
	$temp_data_array = @(@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@())
	$temp_dkim_arry = @(@(),@(),@())

	[xml]$DMARC_xml_file = Get-Content -Path $file_path
	$namespaceURI = @{ 'ns' = $DMARC_xml_file.DocumentElement.NamespaceURI } # Extraction du Namespace
	
	# Va remplir $temp_data_array avec les différentes infos les plus importantes du fichier xml chargé
	# Dans l'ordre: Origine du rapport; Date Debut (UTC); Date Fin (UTC); IP Source; Destination; Return-Path; Domaine Source; DKIM Match; SPF Match; DMARC Résultat; DKIM Resultat;
	# DKIM Domain; DKIM Selector; SPF résultat; SPF Domain;
	
	# (Select-Xml "<path>" $<fichier xml>).Node.InnerText -> sélectionne le Node (<exemple de node>) et retourne une liste de nodes. On garde
	# ensuite la valeur texte de chaque node. Les fichiers avec Namespace doivent spécifier ns: avec le Namespace en question
	
	$temp_data_array[0] += (Select-Xml "//feedback/report_metadata/org_name" $DMARC_xml_file -Namespace $namespaceURI).Node.InnerText
	$temp_data_array[1] += (Select-Xml "//feedback/report_metadata/date_range/begin" $DMARC_xml_file -Namespace $namespaceURI).Node.InnerText
	$temp_data_array[2] += (Select-Xml "//feedback/report_metadata/date_range/end" $DMARC_xml_file -Namespace $namespaceURI).Node.InnerText
	$temp_data_array[3] += (Select-Xml "//feedback/record/row/source_ip" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
		
	$temp_data_array[4] += (Select-Xml "//feedback/record/identifiers/envelope_to" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[5] += (Select-Xml "//feedback/record/identifiers/envelope_from" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[6] += (Select-Xml "//feedback/record/identifiers/header_from" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
		
	$temp_data_array[7] += (Select-Xml "//feedback/record/row/policy_evaluated/dkim" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[8] += (Select-Xml "//feedback/record/row/policy_evaluated/spf" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[9] += (Select-Xml "//feedback/record/row/policy_evaluated/disposition" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	
	$temp_data_array[13] += (Select-Xml "//feedback/record/auth_results/spf/result" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[14] += (Select-Xml "//feedback/record/auth_results/spf/domain" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	
	# Récupère l'ensemble des valeurs brutes DKIM du document
	
	$temp_dkim_arry[0] += (Select-Xml "//feedback/record/auth_results/dkim/result" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_dkim_arry[1] += (Select-Xml "//feedback/record/auth_results/dkim/domain" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }
	$temp_dkim_arry[2] += (Select-Xml "//feedback/record/auth_results/dkim/selector" $DMARC_xml_file).Node | ForEach-Object { $_.InnerText }

	# Chaque <record> peut avoir un maximum de 49 DKIM. Pour garder un nombre de colonnes fixes, on condense les valeurs DKIM ensemble pour chaque <record>
	# pour remplir les lignes des informations DKIM de la matrice $temp_data_array.
	
	$old_index = 0
	$select_idx = 0
	$auth_results_nodes = @() # Pour extraire la liste des informations DKIM par <record>. (1 <auth_results> par <record>, contient les nodes <dkim>)
	$auth_results_nodes += (Select-Xml "//feedback/record/auth_results" $DMARC_xml_file).Node | ForEach-Object { $_.OuterXml }
	for ($i = 0; $i -lt $auth_results_nodes.Length; $i++) {
		$dkimMatches = [regex]::Matches($auth_results_nodes[$i], "<dkim>(.*?)</dkim>") # Identifie toutes les occurences <dkim> dans un seul <record>
		
		# Ajout d'une chaîne de caractères pour initialiser la concaténation de chaînes de charactères
		$temp_data_array[10] += ,""
		$temp_data_array[11] += ,""
		$temp_data_array[12] += ,""
		
		# Prend le nombre de balises <dkim> dans un <record> et concatène en fonction les valeurs extraites de la matrice $temp_dkim_arry pour en faire
		# une seule chaîne de caractères.
		for ($x = $old_index ; $x -lt ($dkimMatches.Count+$old_index); $x++){ 
			$temp_data_array[10][$i] += $temp_dkim_arry[0][$x]+"`n" # result
			$temp_data_array[11][$i] += $temp_dkim_arry[1][$x]+"`n" # domain
		}
		
		# Remplit les valeurs vides si non spécifiées, pour garder le même nombre d'entrées.
		foreach ($match in $dkimMatches) {
			$selector_check = ([regex]::Matches($match.Value, "<selector>").Count) 	# Vérifie si la balise <dkim> contient une valeur <selector>
			if ($selector_check -eq 0){ 											# Si non, ajoute "N/A"
				$temp_data_array[12][$i] += "N/A`n"
			}else{ 																	# Si oui, ajoute la valeur à l'index $select_idx
				$temp_data_array[12][$i] += $temp_dkim_arry[2][$select_idx]+"`n"
				$select_idx++;
			}
		}
		foreach ($idx in @(10,11,12)){
			if($temp_data_array[$idx][($temp_data_array[$idx].Length)-1] -eq ""){
				$temp_data_array[$idx][($temp_data_array[$idx].Length)-1] = "N/A"
			}
		}
		$old_index += $dkimMatches.Count
	}
	
	
	# Convertit les dates UNIX en dates lisibles
	
	$temp_data_array[1][0] = [int64]$temp_data_array[1][0]
	$temp_data_array[2][0] = [int64]$temp_data_array[2][0]
	
	$temp_data_array[1][0] = (Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds($temp_data_array[1][0]))
	$temp_data_array[2][0] = (Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds($temp_data_array[2][0]))

	# Remplit les données manquantes/uniques
		
	for ($i = 1; $i -lt $temp_data_array[3].Length; $i++){ # org_name, start_time, end_time
		$temp_data_array[0] += $temp_data_array[0][0]
		$temp_data_array[1] += $temp_data_array[1][0]
		$temp_data_array[2] += $temp_data_array[2][0]
	}
	for ($i = 0; $i -lt $temp_data_array.Length; $i++){
		if ($temp_data_array[$i][0] -eq $null -and $temp_data_array[$i].Length -eq 1){ # Vérifie que la ligne est vide
			$temp_data_array[$i][0] = "N/A"
			for ($x = 1; $x -lt $temp_data_array[3].Length; $x++){ # receiver info
				$temp_data_array[$i] += ,"N/A"
			}
		}else{
			for ($x = 0; $x -lt $temp_data_array[$i].Length; $x++){
				if($temp_data_array[$i][$x] -eq "" -or $temp_data_array[$i][$x] -eq $null){
					$temp_data_array[$i][$x] = "N/A"
				}
			}
		}
	}
	
	Check-data-processing -auth_array $auth_results_nodes -data_matrix $temp_data_arrays -dkim_array $temp_dkim_arry

	return $temp_data_array
}

# --------------------------------------------------------------------------------------------------------------------------------------------
# Permet d'extraire les informations d'un fichier DMAC .xml, et les garde dans une matrice.
# Permet de supporter les fichiers avec Namespaces (environ 8 cas sur 166, 0.05%)
# -file_path -> chemin complet du fichier .xml
# --------------------------------------------------------------------------------------------------------------------------------------------
function Get-DMARC-wNS-data { # 
	param (
		[string]$file_path
	)
	
	# Rassemblement des données des fichiers xml (un par uns)
	# Chaque <record> est une colonne (donc $temp_data_array[0][0] et $temp_data_array[1][0] appartiennent au même <record>)
	
	$temp_data_array = @(@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@(),@())
	$temp_dkim_arry = @(@(),@(),@())

	[xml]$DMARC_xml_file = Get-Content -Path $file_path
	$namespaceURI = @{ 'ns' = $DMARC_xml_file.DocumentElement.NamespaceURI } # Extraction du Namespace
	
	# Va remplir $temp_data_array avec les différentes infos les plus importantes du fichier xml chargé
	# Dans l'ordre: Origine du rapport; Date Debut (UTC); Date Fin (UTC); IP Source; Destination; Return-Path; Domaine Source; DKIM Match; SPF Match; DMARC Résultat; DKIM Resultat;
	# DKIM Domain; DKIM Selector; SPF résultat; SPF Domain.
	
	# (Select-Xml "<path>" $<fichier xml>).Node.InnerText -> sélectionne le Node (<exemple de node>) et retourne une liste de nodes. On garde
	# ensuite la valeur texte de chaque node. Les fichiers avec Namespace doivent spécifier ns: avec le Namespace en question
	
	$temp_data_array[0] += (Select-Xml "//ns:feedback/ns:report_metadata/ns:org_name" $DMARC_xml_file -Namespace $namespaceURI).Node.InnerText
	$temp_data_array[1] += (Select-Xml "//ns:feedback/ns:report_metadata/ns:date_range/ns:begin" $DMARC_xml_file -Namespace $namespaceURI).Node.InnerText
	$temp_data_array[2] += (Select-Xml "//ns:feedback/ns:report_metadata/ns:date_range/ns:end" $DMARC_xml_file -Namespace $namespaceURI).Node.InnerText
	$temp_data_array[3] += (Select-Xml "//ns:feedback/ns:record/ns:row/ns:source_ip" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
		
	$temp_data_array[4] += (Select-Xml "//ns:feedback/ns:record/ns:identifiers/ns:envelope_to" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[5] += (Select-Xml "//ns:feedback/ns:record/ns:identifiers/ns:envelope_from" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[6] += (Select-Xml "//ns:feedback/ns:record/ns:identifiers/ns:header_from" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
		
	$temp_data_array[7] += (Select-Xml "//ns:feedback/ns:record/ns:row/ns:policy_evaluated/ns:dkim" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[8] += (Select-Xml "//ns:feedback/ns:record/ns:row/ns:policy_evaluated/ns:spf" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[9] += (Select-Xml "//ns:feedback/ns:record/ns:row/ns:policy_evaluated/ns:disposition" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	
	$temp_data_array[13] += (Select-Xml "//ns:feedback/ns:record/ns:auth_results/ns:spf/ns:result" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_data_array[14] += (Select-Xml "//ns:feedback/ns:record/ns:auth_results/ns:spf/ns:domain" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	
	# Récupère l'ensemble des valeurs brutes DKIM du document
	
	$temp_dkim_arry[0] += (Select-Xml "//ns:feedback/ns:record/ns:auth_results/ns:dkim/ns:result" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_dkim_arry[1] += (Select-Xml "//ns:feedback/ns:record/ns:auth_results/ns:dkim/ns:domain" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }
	$temp_dkim_arry[2] += (Select-Xml "//ns:feedback/ns:record/ns:auth_results/ns:dkim/ns:selector" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.InnerText }

	# Chaque <record> peut avoir un maximum de 49 DKIM. Pour garder un nombre de colonnes fixes, on condense les valeurs DKIM ensemble pour chaque <record>
	# pour remplir les lignes des informations DKIM de la matrice $temp_data_array.
	
	$old_index = 0
	$select_idx = 0
	$auth_results_nodes = @() # Pour extraire la liste des informations DKIM par <record>. (1 <auth_results> par <record>, contient les nodes <dkim>)
	$auth_results_nodes += (Select-Xml "//ns:feedback/ns:record/ns:auth_results" $DMARC_xml_file -Namespace $namespaceURI).Node | ForEach-Object { $_.OuterXml }
	for ($i = 0; $i -lt $auth_results_nodes.Length; $i++) {
		$temp_dkim_list = @()
		$dkimMatches = [regex]::Matches($auth_results_nodes[$i], "<dkim>(.*?)</dkim>") # Identifie toutes les occurences <dkim> dans un seul <record>
		
		# Ajout d'une chaîne de caractères pour initialiser la concaténation de chaînes de charactères
		$temp_data_array[10] += ,""
		$temp_data_array[11] += ,""
		$temp_data_array[12] += ,""
		
		# Prend le nombre de balises <dkim> dans un <record> et concatène en fonction les valeurs extraites de la matrice $temp_dkim_arry pour en faire
		# une seule chaîne de caractères.
		for ($x = $old_index ; $x -lt ($dkimMatches.Count+$old_index); $x++){ # combine in a single string all the results and the domain that are from a same auth_results
			$temp_data_array[10][$i] += $temp_dkim_arry[0][$x]+"`n" # result
			$temp_data_array[11][$i] += $temp_dkim_arry[1][$x]+"`n" # domain
		}
		
		# Remplit les valeurs vides si non spécifiées, pour garder le même nombre d'entrées.
		foreach ($match in $dkimMatches) {
			$selector_check = ([regex]::Matches($match.Value, "<selector>").Count) 	# Vérifie si la balise <dkim> contient une valeur <selector>
			if ($selector_check -eq 0){ 											# Si non, ajoute "N/A"
				$temp_data_array[12][$i] += "N/A`n"
			}else{ 																	# Si oui, ajoute la valeur à l'index $select_idx
				$temp_data_array[12][$i] += $temp_dkim_arry[2][$select_idx]+"`n"
				$select_idx++;
			}
		}
		foreach ($idx in @(10,11,12)){
			if($temp_data_array[$idx][($temp_data_array[$idx].Length)-1] -eq ""){
				$temp_data_array[$idx][($temp_data_array[$idx].Length)-1] = "N/A"
			}
		}
		$old_index += $dkimMatches.Count
	}
	
	# Convertit les dates UNIX en dates lisibles
	
	$temp_data_array[1][0] = [int64]$temp_data_array[1][0]
	$temp_data_array[2][0] = [int64]$temp_data_array[2][0]
	
	$temp_data_array[1][0] = (Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds($temp_data_array[1][0]))
	$temp_data_array[2][0] = (Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds($temp_data_array[2][0]))
	
	# Remplit les données manquantes/uniques
		
	for ($i = 1; $i -lt $temp_data_array[3].Length; $i++){ # org_name, start_time, end_time
		$temp_data_array[0] += $temp_data_array[0][0]
		$temp_data_array[1] += $temp_data_array[1][0]
		$temp_data_array[2] += $temp_data_array[2][0]
	}
	for ($i = 0; $i -lt $temp_data_array.Length; $i++){
		if ($temp_data_array[$i][0] -eq $null -and $temp_data_array[$i].Length -eq 1){ # Vérifie que la ligne est vide
			$temp_data_array[$i][0] = "N/A"
			for ($x = 1; $x -lt $temp_data_array[3].Length; $x++){ # receiver info
				$temp_data_array[$i] += ,"N/A"
			}
		}else{
			for ($x = 0; $x -lt $temp_data_array[$i].Length; $x++){
				if($temp_data_array[$i][$x] -eq "" -or $temp_data_array[$i][$x] -eq $null){
					$temp_data_array[$i][$x] = "N/A"
				}
			}
		}
	}
	
	Check-data-processing -auth_array $auth_results_nodes -data_matrix $temp_data_arrays -dkim_array $temp_dkim_arry

	return $temp_data_array
}

# --------------------------------------------------------------------------------------------------------------------------------------------
# Vérifie que les données ont été extraites correctement du fichier .xml.
# -auth_array -> la liste des nodes <auth_results> en tant que chaînes de caractères.
# -data_matrix -> la matrice des informations extraites de Get-DMARC-data.
# -dkim_array -> la liste des informations brutes DKIM extraites du fichier .xml.
# --------------------------------------------------------------------------------------------------------------------------------------------
function Check-data-processing {
	param (
		$auth_array,
		$data_matrix,
		$dkim_array
	)
	
	# Vérifie que chaque contient le même nombre d'entrées.
	$count_dkim = 0
	foreach ($array in $data_matrix){
		if ($array.Length -ne $data_matrix[1].Length){
			Throw "Error: The number of entries isn't equal. There was an error in the process. The file cannot be processed further."	
		}
	}
	
	# Compte le total de nodes <dkim> dans le document.
	foreach ($array in $auth_array){
		$count_dkim += [regex]::Matches($array, "<dkim>(.*?)</dkim>").Count
	}
	# Compare le total de nodes avec le nombre d'entrées dans la liste brute d'informations DKIM.
	foreach ($num in @(0,1)){
		if ($dkim_array[$num].Length -ne $count_dkim -and $dkim_array[$num][0] -ne $null){
			Throw "Error: The number of DKIM isn't equal. There was an error in the process. The file cannot be processed further."	
		}
	}
}

# --------------------------------------------------------------------------------------------------------------------------------------------
# Réarrange la matrice d'informations: on passe de un <record> par colonne à un <record> par ligne (xy -> yx) pour préparer à remplir
# le fichier CSV.
# -data_array -> la matrice des informations extraites de Get-DMARC-data.
# -csv_path -> le chemin complet du fichier csv correspondant au fichier .xml en cours d'analyse.
# --------------------------------------------------------------------------------------------------------------------------------------------
function Reorganize_DMARC_data {
	param (
		$data_array,
		$csv_path
	)
	
	$new_data_array = @()
	# Prend chaque élément d'une colonne pour le rajouter à une nouvelle matrice, colonne par colonne.
	for ($y = 0; $y -lt $data_array[0].Length; $y++) {
		$new_sub_array = @()
		for ($x = 0; $x -lt $data_array.Length; $x++){ 	# Vérification de chaque ligne
			$new_sub_array += ,$data_array[$x][$y]
		}
		$new_data_array += ,$new_sub_array				# Ajout de la liste temporaire à la nouvelle matrice
	}
	
	# /!\ A ne pas déplacer! Mettre cette ligne ailleurs fait que les fichiers .xml avec un seul <report> ne sont pas supportés.
	Fill-DMARC-csv -data_array $new_data_array -path $csv_path
}

# --------------------------------------------------------------------------------------------------------------------------------------------
# Décompresse les fichiers Gzip, Zip, et renomme les fichiers sans extension pour avoir une liste de fichiers .xml uniquement.
# -folder_path -> le chemin complet du dossier contenant les fichiers compressés (qui sera utilisé pour stocker les fichiers décompressés)
# --------------------------------------------------------------------------------------------------------------------------------------------
function Decompressing_Files {
	param (
		$folder_path
	)
	# Décompression des fichiers Gzip
	$gzip_files = Get-ChildItem -Path $folder_path -Filter *.gz # Selection des fichiers avec extension .gz uniquement
	
    foreach ($file in $gzip_files){
		$sourceStream = [System.IO.File]::OpenRead($file.FullName)
		
		# Create the destination path for writing
		$destinationFile = $file.FullName -replace ".gz", "" 	# La majorité des fichiers Gzip se terminent déjà en "<*>.xml.gzip"
		$destinationStream = [System.IO.File]::Create($destinationFile)
		
		# Create a GzipStream for decompression
		$gzipStream = New-Object System.IO.Compression.GzipStream($sourceStream, [System.IO.Compression.CompressionMode]::Decompress)
		
		# Copy the decompressed data to the destination file
		$gzipStream.CopyTo($destinationStream)
		
		# Close the streams
		$gzipStream.Close()
		$destinationStream.Close()
		$sourceStream.Close()
		Remove-Item $file.FullName
	}
	
	# Décompression des fichiers Zip
	$zip_files = Get-ChildItem -Path $folder_path -Filter *.zip
	
    foreach ($file in $zip_files){
		$destinationFolder = Split-Path -Path $file.FullName -Parent
		Add-Type -AssemblyName System.IO.Compression.FileSystem
		[System.IO.Compression.ZipFile]::ExtractToDirectory($file.FullName, $destinationFolder)
		Remove-Item $file.FullName
	}
	
	# Récupère les fichiers décompressés sans extension (Gzip se terminant par "<*>.gz" au lieu de "<*>.xml.gz")
	
	$other_files = Get-ChildItem -Path $folder_path
	
	foreach ($file in $other_files) {
		if (-not $file.PSIsContainer -and $file.Extension -ne ".xml") {
			Rename-Item -Path $file.FullName -NewName "$($file.FullName).xml"
		}
	}
}

# --------------------------------------------------------------------------------------------------------------------------------------------
# Filtre les <records> de la matrice donnée, et garde uniquement celles avec une mention de 'fail'. Crée ensuite un fichier CSV(FR) avec
# ces <records> spécifiques.
# -data_array -> la matrice des informations extraites de Get-DMARC-data.
# -path -> le chemin complet du fichier csv correspondant au fichier .xml en cours d'analyse.
# --------------------------------------------------------------------------------------------------------------------------------------------
function Fill-DMARC-csv {
	param (
		$data_array,
		[string]$path
	)
	
	$check = $true							# Pour identifier un fichier qui n'a que "pass" en valeur
	$data = @()
	$fields_to_check = @(7,8,10,13) 			# Vérifie spécifiquement les colonnes DKIM Match; SPF Match; DKIM Result; SPF Result.
	foreach ($entry in $data_array){
		$sub_array = @()
		foreach($num in $fields_to_check){
			$temp_string = $entry[$num] -replace "`n", ""
			if (-not ($temp_string -match "^[pass]+$")){ 	# Pour toutes les valeurs autre que "pass".
				$check = $false
				foreach ($value in $entry) {
					$sub_array += ,$value 	# Copie une par unes les entrées de ce <record> spécifique
				}
				$data += ,$sub_array		# Et rajoute la liste temporaire en tant que nouvelle ligne d'une nouvelle matrice.
				break
			}
		}
	}
	
	if ( $check ){
		Write-Host "Aucun record suspect. Les données ne sont pas ajoutées aux feuilles Excel..."
		
	}else{
	
		$updated_data = @()
		# Si le fichier CSV existe déjà, récupérer les données du document.
		if (Test-Path -Path $path) {
			$existing_data = Import-Csv -Path $path -Delimiter ';'
			$updated_data += $existing_data
		}
		
		# Remplit ensuite ligne par ligne $updated_data avec les nouvelles valeurs filtrées.
		foreach ($entry in $data){
			$updated_data += [PSCustomObject]@{
				"Origine du rapport" = $entry[0]
				"Date Debut (UTC)" = $entry[1]
				"Date Fin (UTC)" = $entry[2]
				"IP Source" = $entry[3]
				"Destination" = $entry[4]
				"Domaine Source" = $entry[6]
				"Return-Path" = $entry[5]
				"DKIM Match" = $entry[7]
				"SPF Match" = $entry[8]
				"DMARC Resultat" = $entry[9]
				"DKIM Resultat" = $entry[10]
				"DKIM Domaine" = $entry[11]
				"DKIM Selector" = $entry[12]
				"SPF Resultat" = $entry[13]
				"SPF Domaine" = $entry[14]
			}
		}
		
		# Si $updated_data n'est pas vide, écrase l'ancien CSV/crée le CSV spécifiquement en Français.
		if ($updated_data){
			$csv_content = $updated_data | ConvertTo-Csv -Delimiter ';' -NoTypeInformation
			$csv_content | Out-File -FilePath $path -Encoding UTF8
		}
	}
}

# --------------------------------------------------------------------------------------------------------------------------------------------
# Fonction principale du document pour appeler les autres fonctions.
# -folder_path -> le chemin complet du dossier utilisé pour le script.
# --------------------------------------------------------------------------------------------------------------------------------------------
function Main {
	
	# Explications du script
	
	Write-Host "`nCe script sert à créer des fichiers CSV rassemblant les rapports non-valides de fichiers XML compressés."
	Write-Host "Le programme s'occupera de:`n  1. Décompresser les fichiers XML compressés;`n  2. Extraire les rapports non-valides de ces fichiers;`n  3. Trier ces rapports par domaine et les rajouter dans des fichier CSV."
	Write-Host "L'ensemble de ces étapes seront directement effectuées dans un seul dossier. Le dossier doit contenir les fichiers XML compressés, et contiendra les fichiers XML décompressés et les fichiers CSV.`n"
	Write-Host "  [Note] Pour une description plus détaillée du programme, ainsi qu'une explication des éléments contenus dans les fichiers CSV, veuillez-vous réferrer à la documentation publiée sur Github:"
	Write-Host	"  https://github.com/Nephrys/DMARC-XML-to-CSV/tree/main?tab=readme-ov-file"
	
	# Récupère un chemin valide
	
	Do {
		$custom_path = Read-Host "`nVeuillez entrer un chemin complet valide "
	}While((-not ($custom_path -match "[a-z]")) -or (-not (Test-Path -Path $custom_path)))
	if (-not ($custom_path.EndsWith("\"))){
		$custom_path += "\"
	}
	
	# Decompression des fichiers compressés
	Decompressing_Files -folder_path $custom_path
	
	# Création d'un dossier "Analyzed" pour y déplacer les fichiers .xml anaylsés.
	$poubelle_path = $custom_path + "Analyzed"
	if (-not (Test-Path -Path $poubelle_path)) { # Crée le dossier s'il n'existe pas encore.
        New-Item -Path $poubelle_path -ItemType Directory | Out-Null
    }
	
	# Création d'un dossier "Exceptions" pour y déplacer les fichiers qui ont déclenché une erreur.
	$error_path = $custom_path + "Exceptions"
	if (-not (Test-Path -Path $error_path)) { # Crée le dossier s'il n'existe pas encore.
        New-Item -Path $error_path -ItemType Directory | Out-Null
    }
	
	# Création d'un dossier "Rapports" pour y stocker les fichiers CSV.
	$csv_path = $custom_path + "Rapports\"
	if (-not (Test-Path -Path $csv_path)) { # Crée le dossier s'il n'existe pas encore.
        New-Item -Path $csv_path -ItemType Directory | Out-Null
    }
	
	# Création d'un dossier pour stocker les XML en double avec le dossier "Analyzed"
	$double_path = $custom_path + "Doublons\"
	if (-not (Test-Path -Path $double_path)) { # Crée le dossier s'il n'existe pas encore.
        New-Item -Path $double_path -ItemType Directory | Out-Null
    }
	
	# Récupère la liste de fichiers .xml dans le dossier, et les traite un par uns.
	$xml_files = Get-ChildItem -Path $custom_path -Filter *.xml
	Write-Host "Debut de l'analyse....................................................................."
	foreach ($file in $xml_files){
		
		Write-Host "`nAnalyse de ",$file,"..."
		
		# Vérifie si le fichier a déjà été analysé
		$temp_path = Join-Path $poubelle_path $file
		if (-not (Test-Path $temp_path)) {
			
			try {
			[xml]$temp_xml_file = Get-Content -Path $file.FullName
			
			# Vérifie si le document .xml utilise des Namespaces, et lance la fonction d'extraction de données correspondante.
			if ($temp_xml_file.DocumentElement.NamespaceURI){
				$namespaceURI = $temp_xml_file.DocumentElement.NamespaceURI
				# Récupère le nom du domaine concerné par le rapport.
				$target_domain = (Select-Xml "//ns:feedback/ns:policy_published/ns:domain" $temp_xml_file -Namespace @{ 'ns' = $namespaceURI }).Node.InnerText
				$og_DMARC_data = Get-DMARC-wNS-data -file_path $file.FullName
				
			}else{
				# Récupère le nom du domaine concerné par le rapport.
				$target_domain = (Select-Xml "//feedback/policy_published/domain" $temp_xml_file).Node.InnerText
				$og_DMARC_data = Get-DMARC-data -file_path $file.FullName
			}
			# Détermine le nom du fichier CSV à remplir en fonction du domaine extrait plus tôt.
			$DMARC_data = Reorganize_DMARC_data -data_array $og_DMARC_data -csv_path ($csv_path+"DMARC_report-$target_domain.csv")

			# S'il n'y a pas d'erreur à la fun du processus, déplacer le fichier dans le dossier "Analyzed"
			Move-Item -Path $file.FullName -Destination $poubelle_path | Out-Null
			
			} catch {
				# En cas d'erreur, déplace le fichier dans le dossier "Exceptions".
				Write-Output "`n /!\ Erreur de traitement du fichier. Deplacement du fichier...`n.........................................."
				Move-Item -Path $file.FullName -Destination $error_path | Out-Null
			}
			
		} else {
			Write-Host "   /!\ Doublon de fichier! On passe au suivant... `n" 
			Move-Item -Path $file.FullName -Destination $double_path | Out-Null
		}
	}
	Write-Host "Fini!"
}

# Lance la fonction principale.
[console]::OutputEncoding = [System.Text.Encoding]::UTF8
Main