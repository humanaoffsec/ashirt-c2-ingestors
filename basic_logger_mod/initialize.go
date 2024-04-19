package my_logger

import (
	"github.com/MythicMeta/MythicContainer/loggingstructs"
)

func Initialize() {
	myLoggerName := "my_logger"
	myLogger := loggingstructs.LoggingDefinition{
		LogToFilePath:  "mythic.log",
		LogLevel:       "info",
		LogMaxSizeInMB: 100,
		LogMaxBackups:  10,
		NewCallbackFunction: func(input loggingstructs.NewCallbackLog) {
			loggingstructs.AllLoggingData.Get(myLoggerName).LogInfo(input.Action, "data", input)
		},
		NewTaskFunction: func(input loggingstructs.NewTaskLog) {
			loggingstructs.AllLoggingData.Get(myLoggerName).LogInfo(input.Action, "data", input.Data)
		},
		NewPayloadFunction: func(input loggingstructs.NewPayloadLog) {
		},
		NewKeylogFunction: func(input loggingstructs.NewKeylogLog) {
		},
		NewCredentialFunction: func(input loggingstructs.NewCredentialLog) {
		},
		NewArtifactFunction: func(input loggingstructs.NewArtifactLog) {
		},
		NewFileFunction: func(input loggingstructs.NewFileLog) {
		},
		NewResponseFunction: func(input loggingstructs.NewResponseLog) {
			loggingstructs.AllLoggingData.Get(myLoggerName).LogInfo(input.Action, "data", input.Data)
		},
	}
	loggingstructs.AllLoggingData.Get(myLoggerName).AddLoggingDefinition(myLogger)
}
