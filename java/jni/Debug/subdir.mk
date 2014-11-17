################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../client.c 

OBJS += \
./client.o 

C_DEPS += \
./client.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I../../../src/safe_lib/include -I"${CISCOSSL_HOME}/include" -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" -I"${EST_HOME}/include" -fPIC -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


