macro(add_unit_test test)
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} PRIVATE rapl_stopwatch)
    add_test(${test} ${test})
endmacro(add_unit_test)

add_unit_test(test_sleep1)
set_tests_properties(test_sleep1 PROPERTIES TIMEOUT 1.5) 

add_unit_test(test_sleep40)
set_tests_properties(test_sleep40 PROPERTIES TIMEOUT 40.5) 
