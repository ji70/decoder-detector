# decoder-detector

Описание структуры проекта:

- labels - папка, содержащая ParsingDecisionTree в файлах

- new_samples - содержит данные в следующем виде:

    -- каждая папка содержит train/test c запросами в виде plain_text
    
    -- в каждой папке train/test есть папка parsed, в которой лежат json файлы, содержащие объекты ParsedHttpRequest
    
    
data_processing.ipynd - составляет из файлов train.csv и test.csv

decoding.py - содержит функции по обработке значения (применимости всех декодеров)

parse_headers.py - читает из plain_text текст и создает вспомогательный json со словарем заголовков

processing_in_waf.py - заполняет папки parsed

testing_decoder.py - содержит функции для обхода всех элементов дерева, отсюда потенциально вызывается функция обработки значений
