(load-extension "tsx-1.1/tsx")
(define (db-create sqlite query)
	(define stmt (sqlite-prepare sqlite query))
	(sqlite-step stmt)
	(sqlite-finalize stmt))

(define (db-insert sqlite query)
	(define stmt (sqlite-prepare sqlite query))
	(sqlite-step stmt)
	(sqlite-finalize stmt))

(define (db-select sqlite query cols)
	(define stmt (sqlite-prepare sqlite query))
	(let loop ((row (sqlite-step stmt)))
  		(if (eq? row #f)
    		#t
    		(begin
				(do ((cnt 0 (+ cnt 1)))
		  			((> cnt cols))
		  			(define col (sqlite-column stmt cnt))
					(if (string? col) (display (string-append col " "))))
		(newline)
	(loop (sqlite-step stmt)))))
(sqlite-finalize stmt))

(delete-file "test.db")
(define sqlite (sqlite-open "test.db"))
(db-create sqlite "CREATE TABLE test (a varchar, b varchar)")
(db-insert sqlite "INSERT INTO test VALUES ('it', 'works')")
(db-select sqlite "SELECT * FROM test" 2)
(sqlite-close sqlite)

