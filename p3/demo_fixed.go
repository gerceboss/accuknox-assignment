package main

import (
	"fmt"
	"sync"
)

// Fixed version with proper synchronization
func main() {
    cnp := make(chan func(), 10)
    var wg sync.WaitGroup
    
    // Start 4 worker goroutines
    for i := 0; i < 4; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            fmt.Printf("Worker %d started\n", workerID)
            for f := range cnp {
                fmt.Printf("Worker %d executing function\n", workerID)
                f()
            }
            fmt.Printf("Worker %d finished\n", workerID)
        }(i)
    }
    
    // Send functions to the channel
    cnp <- func() {
        fmt.Println("HERE1 - Function executed!")
    }
    
    cnp <- func() {
        fmt.Println("HERE2 - Another function executed!")
    }
    
    cnp <- func() {
        fmt.Println("HERE3 - Third function executed!")
    }
    
    // Close the channel to signal workers to stop
    close(cnp)
    
    // Wait for all workers to finish
    wg.Wait()
    
    fmt.Println("Hello - All workers finished!")
}