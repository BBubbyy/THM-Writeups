# SQL Fundamentals Cheat Sheet

## 1. Connecting & Selecting DBs

|Command|Function|
|---|---|
|`mysql -u [user] -p`|Log in to MySQL (e.g., `mysql -u root -p`)|
|`SHOW DATABASES;`|Show all databases|
|`USE [db_name];`|Select a database to work with|
|`SHOW TABLES;`|Show all tables in the selected DB|
|`DESCRIBE [table_name];`|Show the column structure of a table|

## 2. Reading & Searching Data

|Command|Function|
|---|---|
|`SELECT * FROM [table];`|Get "all columns" from a table|
|`SELECT [col1], [col2] FROM [table];`|Get "specific columns"|
|`... WHERE [condition];`|"Filter" rows (e.g., `WHERE id = 1`)|
|`... WHERE col LIKE '%text%';`|Find rows where the column "contains" the word 'text'|
|`... WHERE col1 = 'A' AND col2 = 'B';`|Filter using "AND" (both must be true)|
|`... WHERE col1 = 'A' OR col2 = 'B';`|Filter using "OR" (either can be true)|

## 3. Manipulating Data

|Command|Function|
|---|---|
|`INSERT INTO [table] (col1, col2) VALUES (val1, val2);`|"Add" a new row of data|
|`UPDATE [table] SET col1 = val1 WHERE id = 1;`|"Modify" data in a row (Don't forget `WHERE`)|
|`DELETE FROM [table] WHERE id = 1;`|"Delete" a row (Don't forget `WHERE`)|

## 4. Grouping & Sorting

|Command|Function|
|---|---|
|`SELECT DISTINCT [col] FROM [table];`|Show only "unique" results|
|`SELECT ... ORDER BY [col] ASC;`|"Sort" results ascending|
|`SELECT ... ORDER BY [col] DESC;`|"Sort" results descending|
|`SELECT [col], COUNT(*) FROM [table] GROUP BY [col];`|"Group" rows and "count" members of each group|

## 5. Common Functions

|Command|Function|
|---|---|
|`COUNT(*)`|Count the number of rows|
|`CONCAT(str1, str2)`|Join strings|
|`GROUP_CONCAT(col)`|(SQL Injection) Join data from multiple rows into one line|
|`SUM(col)` / `MAX(col)` / `MIN(col)`|Sum / Max value / Min value|
